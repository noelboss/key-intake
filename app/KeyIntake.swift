// KeyIntake — native window that takes API keys and stores them in the login keychain.
// Values never reach argv, stdout/stderr or a file: they travel over stdin into `/usr/bin/security -i`,
// so the item gets security's own ACL and later `security find-generic-password -w` reads stay dialog-free.
//
// usage: KeyIntake NAME[=label] … --url <https link> --steps "<step> | <step>" [NAME… --url … --steps …] [--keychain <absolute path> --stdin-values]
//        every group of names ends with its creation page and steps; test mode: values on stdin, throwaway keychain
// env:    KEY_INTAKE_ACCOUNT (account for new entries) · KEY_INTAKE_BROWSER (app for the page) · KEY_INTAKE_LANG (en|de)
//         KEY_INTAKE_SNAPSHOT=<png path> renders the window for docs and exits
// stdout: one line per name — stored NAME | skipped NAME | failed NAME <reason>
// exit:   0 at least one stored · 1 cancelled or nothing stored · 2 error (any failed line)

import AppKit
import Security

let env = ProcessInfo.processInfo.environment
let defaultAccount = env["KEY_INTAKE_ACCOUNT"].flatMap { $0.isEmpty ? nil : $0 } ?? NSUserName()
let german = (env["KEY_INTAKE_LANG"] ?? Locale.preferredLanguages.first ?? "en").lowercased().hasPrefix("de")
let maxNote = 200
let maxStep = 300
let maxSteps = 12
let maxURL = 2048
let initialWidth: CGFloat = 640
let headerTop: CGFloat = 40
let maxCommandLine = 4090  // `security -i` rejects longer lines; 4000 hex digits fail, 3960 pass

enum Lookup: Equatable {
	case new
	case existing(account: String)
	case ambiguous(count: Int)
	case error
}

struct Guide {
	let url: URL
	let steps: [String]
}

struct Entry {
	let name: String
	let note: String
	let guide: Int
}

enum Outcome {
	case stored
	case skipped
	case failed(String)
}

func t(_ en: String, _ de: String) -> String { german ? de : en }

func fail(_ message: String) -> Never {
	FileHandle.standardError.write(Data((message + "\n").utf8))
	exit(2)
}

func validName(_ name: String) -> Bool {
	guard (1...128).contains(name.utf8.count) else { return false }
	let alnum: (UInt8) -> Bool = { c in (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) }
	return alnum(name.utf8.first!) && name.utf8.allSatisfy { c in alnum(c) || c == 95 || c == 46 || c == 45 }
}

func cleanText(_ text: String, limit: Int) -> String {
	let printable = text.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }
	return String(String.UnicodeScalarView(printable).prefix(limit))
}

func validURL(_ text: String) -> URL? {
	guard text.utf8.count <= maxURL, text.hasPrefix("https://"),
		!text.unicodeScalars.contains(where: { CharacterSet.whitespacesAndNewlines.contains($0) || CharacterSet.controlCharacters.contains($0) }),
		let url = URL(string: text), url.scheme == "https", let host = url.host, !host.isEmpty
	else { return nil }
	return url
}

func parseSteps(_ text: String) -> [String] {
	text.split(separator: "|").map { trimmed(cleanText(String($0), limit: maxStep)) }.filter { !$0.isEmpty }
}

// MARK: keychain

final class Keychain {
	let ref: SecKeychain
	let path: String
	let securityPath: String
	let injectedLookupStatus: OSStatus?

	// securityPath and injectedLookupStatus are test-mode hooks; the normal run always uses /usr/bin/security and real statuses.
	init?(path explicit: String?, securityPath: String = "/usr/bin/security", injectedLookupStatus: OSStatus? = nil) {
		self.securityPath = securityPath
		self.injectedLookupStatus = injectedLookupStatus
		var kc: SecKeychain?
		if let explicit = explicit {
			guard SecKeychainOpen(explicit, &kc) == errSecSuccess, kc != nil else { return nil }
		} else {
			guard SecKeychainCopyDefault(&kc) == errSecSuccess, kc != nil else { return nil }
		}
		var len: UInt32 = 1024
		var buf = [CChar](repeating: 0, count: Int(len))
		guard SecKeychainGetPath(kc!, &len, &buf) == errSecSuccess else { return nil }
		ref = kc!
		path = String(cString: buf)
	}

	// Attributes only, never data: finds every duplicate and cannot trigger a dialog.
	func lookup(_ name: String) -> Lookup {
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: name,
			kSecMatchLimit as String: kSecMatchLimitAll,
			kSecReturnAttributes as String: true,
			kSecMatchSearchList as String: [ref],
		]
		var out: CFTypeRef?
		let status = injectedLookupStatus ?? SecItemCopyMatching(query as CFDictionary, &out)
		if status == errSecItemNotFound { return .new }
		guard status == errSecSuccess, let items = out as? [[String: Any]], !items.isEmpty else { return .error }
		if items.count > 1 { return .ambiguous(count: items.count) }
		return .existing(account: (items[0][kSecAttrAccount as String] as? String) ?? "")
	}

	func store(name: String, account: String, value: String) -> String? {
		if account.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) {
			return "unsupported account"
		}
		let hex = value.utf8.map { String(format: "%02x", $0) }.joined()
		let command = "add-generic-password -U -s \(quote(name)) -a \(quote(account)) -X \(hex) \(quote(path))\n"
		if command.utf8.count > maxCommandLine { return "value too long" }

		let task = Process()
		task.executableURL = URL(fileURLWithPath: securityPath)
		task.arguments = ["-i"]
		let stdin = Pipe(), stderr = Pipe()
		task.standardInput = stdin
		task.standardOutput = FileHandle.nullDevice
		task.standardError = stderr
		do { try task.run() } catch { return "security not startable" }
		stdin.fileHandleForWriting.write(Data(command.utf8))
		try? stdin.fileHandleForWriting.close()
		let err = String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
		task.waitUntilExit()

		// Reasons are mapped, never echoed: stderr text of a failed write must not be able to carry a value.
		if task.terminationStatus != 0 || err.contains("security:") || err.contains("SecKeychain") {
			let lower = err.lowercased()
			if lower.contains("interaction is not allowed") || lower.contains("locked") { return "keychain locked" }
			if lower.contains("could not be found") { return "keychain not found" }
			if lower.contains("denied") || lower.contains("authorization") { return "access denied" }
			return "security write failed"
		}
		if case .existing = lookup(name) { return nil }
		return "entry not found after write"
	}

	private func quote(_ s: String) -> String {
		"\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
	}
}

func accountFor(_ lookup: Lookup) -> String {
	if case .existing(let account) = lookup { return account }
	return defaultAccount
}

func trimmed(_ s: String) -> String { s.trimmingCharacters(in: .whitespacesAndNewlines) }

func report(_ entries: [Entry], _ outcomes: [String: Outcome]) -> Int32 {
	var stored = 0, failed = 0
	for e in entries {
		switch outcomes[e.name] ?? .skipped {
		case .stored: stored += 1; print("stored \(e.name)")
		case .skipped: print("skipped \(e.name)")
		case .failed(let reason): failed += 1; print("failed \(e.name) \(reason)")
		}
	}
	fflush(stdout)
	if failed > 0 { return 2 }
	return stored > 0 ? 0 : 1
}

// MARK: test mode (values from stdin into a throwaway keychain)

func runTestMode(entries: [Entry], states: [Lookup], keychain: Keychain) -> Int32 {
	var values: [String: (value: String, replace: Bool)] = [:]
	while let line = readLine(strippingNewline: true) {
		let parts = line.components(separatedBy: "\t")
		guard parts.count >= 2 else { continue }
		let value = parts[1].replacingOccurrences(of: "\\n", with: "\n")
		values[parts[0]] = (value, parts.count > 2 && parts[2] == "replace")
	}
	var outcomes: [String: Outcome] = [:]
	for (e, state) in zip(entries, states) {
		if case .ambiguous = state { outcomes[e.name] = .failed("ambiguous"); continue }
		if case .error = state { outcomes[e.name] = .failed("lookup error"); continue }
		guard let given = values[e.name], !trimmed(given.value).isEmpty else { outcomes[e.name] = .skipped; continue }
		if case .existing = state, !given.replace { outcomes[e.name] = .skipped; continue }
		if keychain.lookup(e.name) != state { outcomes[e.name] = .failed("state changed"); continue }
		if let reason = keychain.store(name: e.name, account: accountFor(state), value: trimmed(given.value)) {
			outcomes[e.name] = .failed(reason)
		} else {
			outcomes[e.name] = .stored
		}
	}
	return report(entries, outcomes)
}

// MARK: window

final class FlippedView: NSView { override var isFlipped: Bool { true } }

enum Tone {
	case neutral, ok, warn, error

	var color: NSColor {
		switch self {
		case .neutral: return .secondaryLabelColor
		case .ok: return .systemGreen
		case .warn: return .systemOrange
		case .error: return .systemRed
		}
	}
}

final class Chip: NSView {
	private let label = NSTextField(labelWithString: "")
	private var tone = Tone.neutral

	override init(frame: NSRect) {
		super.init(frame: frame)
		wantsLayer = true
		label.font = NSFont.systemFont(ofSize: 11, weight: .medium)
		label.translatesAutoresizingMaskIntoConstraints = false
		addSubview(label)
		NSLayoutConstraint.activate([
			label.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 8),
			label.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -8),
			label.topAnchor.constraint(equalTo: topAnchor, constant: 2),
			label.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -2),
		])
		setContentHuggingPriority(.required, for: .horizontal)
	}

	required init?(coder: NSCoder) { fatalError() }

	func set(_ text: String, _ tone: Tone) {
		label.stringValue = text
		label.textColor = tone == .neutral ? .secondaryLabelColor : .labelColor
		self.tone = tone
		needsDisplay = true
	}

	override var wantsUpdateLayer: Bool { true }

	override func updateLayer() {
		layer?.backgroundColor = tone.color.withAlphaComponent(tone == .neutral ? 0.12 : 0.2).cgColor
	}

	override func layout() {
		super.layout()
		layer?.cornerRadius = bounds.height / 2
	}
}

final class Card: NSView {
	override init(frame: NSRect) {
		super.init(frame: frame)
		wantsLayer = true
		layer?.cornerRadius = 12
		layer?.borderWidth = 1
	}

	required init?(coder: NSCoder) { fatalError() }

	override var wantsUpdateLayer: Bool { true }

	override func updateLayer() {
		layer?.backgroundColor = NSColor.controlBackgroundColor.cgColor
		layer?.borderColor = NSColor.separatorColor.cgColor
	}
}

final class Row {
	let entry: Entry
	let state: Lookup
	let field = NSSecureTextField()
	let chip = Chip()
	let count = NSTextField(labelWithString: "")
	let replace = NSButton(checkboxWithTitle: t("replace", "ersetzen"), target: nil, action: nil)
	let copy = NSButton(title: t("Copy", "Kopieren"), target: nil, action: nil)
	var done = false

	init(entry: Entry, state: Lookup) {
		self.entry = entry
		self.state = state
	}

	var chipText: String {
		switch state {
		case .new: return t("new", "neu")
		case .existing: return t("replaces existing value", "ersetzt vorhandenen Wert")
		case .ambiguous(let n): return t("ambiguous (\(n) entries), clean up first", "mehrdeutig (\(n) Einträge), erst bereinigen")
		case .error: return t("lookup failed, row locked", "Abfrage fehlgeschlagen, Zeile gesperrt")
		}
	}

	var chipTone: Tone {
		switch state {
		case .new: return .neutral
		case .existing: return .warn
		case .ambiguous, .error: return .error
		}
	}

	var hint: String {
		entry.note.isEmpty
			? t("Paste the value from the page here", "Wert von der Seite hier einfügen")
			: t("Paste here: “\(entry.note)” from the page", "Hier einfügen: «\(entry.note)» von der Seite")
	}

	var active: Bool {
		switch state {
		case .ambiguous, .error: return false
		default: return !done
		}
	}

	var wantsSave: Bool {
		guard active, !trimmed(field.stringValue).isEmpty else { return false }
		if case .existing = state { return replace.state == .on }
		return true
	}
}

// Opens in KEY_INTAKE_BROWSER when set and installed, otherwise in the default browser.
func openPage(_ url: URL) {
	guard let browser = env["KEY_INTAKE_BROWSER"], !browser.isEmpty else { NSWorkspace.shared.open(url); return }
	let task = Process()
	task.executableURL = URL(fileURLWithPath: "/usr/bin/open")
	task.arguments = ["-a", browser, url.absoluteString]
	task.standardOutput = FileHandle.nullDevice
	task.standardError = FileHandle.nullDevice
	task.terminationHandler = { t in
		if t.terminationStatus != 0 { DispatchQueue.main.async { NSWorkspace.shared.open(url) } }
	}
	do { try task.run() } catch { NSWorkspace.shared.open(url) }
}

func symbol(_ name: String, _ label: String) -> NSImage? {
	NSImage(systemSymbolName: name, accessibilityDescription: label)
}

final class Controller: NSObject, NSApplicationDelegate, NSWindowDelegate, NSTextFieldDelegate {
	let entries: [Entry]
	let guides: [Guide]
	let keychain: Keychain
	var rows: [Row] = []
	var outcomes: [String: Outcome] = [:]
	let window: NSWindow
	let saveButton = NSButton(title: t("Save", "Speichern"), target: nil, action: nil)
	let cancelButton = NSButton(title: t("Cancel", "Abbrechen"), target: nil, action: nil)
	let message = NSTextField(wrappingLabelWithString: "")

	init(entries: [Entry], guides: [Guide], states: [Lookup], keychain: Keychain) {
		self.entries = entries
		self.guides = guides
		self.keychain = keychain
		window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: initialWidth, height: 400),
			styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView], backing: .buffered, defer: false)
		super.init()
		for (e, state) in zip(entries, states) {
			if case .ambiguous = state { outcomes[e.name] = .failed("ambiguous") }
			if case .error = state { outcomes[e.name] = .failed("lookup error") }
			rows.append(Row(entry: e, state: state))
		}
	}

	// Floats beside the browser so the steps stay readable while the user works on the page.
	func applicationDidFinishLaunching(_ notification: Notification) {
		buildMenu()
		buildWindow()
		window.delegate = self
		window.level = .floating
		if let visible = (NSScreen.main ?? window.screen)?.visibleFrame {
			window.setFrameTopLeftPoint(NSPoint(x: visible.maxX - window.frame.width - 24, y: visible.maxY - 24))
		}
		window.makeKeyAndOrderFront(nil)
		NSApp.activate(ignoringOtherApps: true)
		if let first = rows.first(where: { $0.active }) { window.makeFirstResponder(first.field) }
		refresh()
		if let path = env["KEY_INTAKE_SNAPSHOT"] {
			DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.snapshot(to: path) }
			return
		}
		if let guide = guides.first { openPage(guide.url) }
	}

	// Renders the window into a PNG for the README, then exits without storing anything or opening a page.
	func snapshot(to path: String) {
		guard let view = window.contentView?.superview, let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { exit(2) }
		view.cacheDisplay(in: view.bounds, to: rep)
		guard let png = rep.representation(using: .png, properties: [:]), (try? png.write(to: URL(fileURLWithPath: path))) != nil else { exit(2) }
		exit(1)
	}

	func buildMenu() {
		let main = NSMenu()
		let appItem = NSMenuItem()
		main.addItem(appItem)
		let appMenu = NSMenu()
		appMenu.addItem(withTitle: t("Quit", "Beenden"), action: #selector(cancel), keyEquivalent: "q").target = self
		appItem.submenu = appMenu
		let editItem = NSMenuItem()
		main.addItem(editItem)
		let edit = NSMenu(title: t("Edit", "Bearbeiten"))
		edit.addItem(withTitle: t("Cut", "Ausschneiden"), action: #selector(NSText.cut(_:)), keyEquivalent: "x")
		edit.addItem(withTitle: t("Copy", "Kopieren"), action: #selector(NSText.copy(_:)), keyEquivalent: "c")
		edit.addItem(withTitle: t("Paste", "Einsetzen"), action: #selector(NSText.paste(_:)), keyEquivalent: "v")
		edit.addItem(withTitle: t("Select All", "Alles auswählen"), action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
		editItem.submenu = edit
		NSApp.mainMenu = main
	}

	func buildWindow() {
		window.title = t("Enter keys", "Key eingeben")
		window.titleVisibility = .hidden
		window.titlebarAppearsTransparent = true
		window.isMovableByWindowBackground = true

		let stack = NSStackView()
		stack.orientation = .vertical
		stack.alignment = .leading
		stack.spacing = 12
		stack.translatesAutoresizingMaskIntoConstraints = false

		for (index, guide) in guides.enumerated() {
			let card = card(for: guide, index: index, rows: rows.filter { $0.entry.guide == index })
			stack.addArrangedSubview(card)
			card.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
		}

		let container = FlippedView()
		container.translatesAutoresizingMaskIntoConstraints = false
		container.addSubview(stack)
		NSLayoutConstraint.activate([
			stack.topAnchor.constraint(equalTo: container.topAnchor, constant: 4),
			stack.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 24),
			stack.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -24),
			stack.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -12),
		])
		let measure = container.widthAnchor.constraint(equalToConstant: initialWidth)
		measure.isActive = true
		container.layoutSubtreeIfNeeded()
		let screenHeight = (NSScreen.main?.visibleFrame.height ?? 900) - 260
		let listHeight = min(container.fittingSize.height, max(screenHeight, 320))
		measure.isActive = false

		let scroll = NSScrollView()
		scroll.hasVerticalScroller = true
		scroll.drawsBackground = false
		scroll.automaticallyAdjustsContentInsets = false
		scroll.translatesAutoresizingMaskIntoConstraints = false
		scroll.documentView = container
		let clip = scroll.contentView
		NSLayoutConstraint.activate([
			container.topAnchor.constraint(equalTo: clip.topAnchor),
			container.leadingAnchor.constraint(equalTo: clip.leadingAnchor),
			container.widthAnchor.constraint(equalTo: clip.widthAnchor),
		])

		let header = buildHeader()
		let bar = buildBar()

		let root = NSView()
		for v in [header, scroll, bar] {
			v.translatesAutoresizingMaskIntoConstraints = false
			root.addSubview(v)
		}
		NSLayoutConstraint.activate([
			header.topAnchor.constraint(equalTo: root.topAnchor, constant: headerTop),
			header.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
			header.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
			scroll.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 18),
			scroll.leadingAnchor.constraint(equalTo: root.leadingAnchor),
			scroll.trailingAnchor.constraint(equalTo: root.trailingAnchor),
			scroll.bottomAnchor.constraint(equalTo: bar.topAnchor, constant: -8),
			bar.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 24),
			bar.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -24),
			bar.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -18),
		])
		window.contentView = root
		root.layoutSubtreeIfNeeded()
		let chrome = header.frame.height + bar.frame.height + headerTop + 18 + 8 + 18
		window.setContentSize(NSSize(width: initialWidth, height: chrome + listHeight))
		window.contentMinSize = NSSize(width: 520, height: chrome + min(listHeight, 220))
		window.center()
	}

	func buildHeader() -> NSView {
		let title = NSTextField(labelWithString: t("Enter keys", "Key eingeben"))
		title.font = NSFont.systemFont(ofSize: 22, weight: .semibold)
		let sub = NSTextField(wrappingLabelWithString: t(
			"Create the key on the page, paste the values here. They go straight into your login keychain and stay out of chat, logs and files.",
			"Schlüssel auf der Seite anlegen, Werte hier einfügen. Sie landen direkt im Login-Schlüsselbund und bleiben aus Chat, Logs und Dateien."))
		sub.font = NSFont.systemFont(ofSize: 12)
		sub.textColor = .secondaryLabelColor
		sub.maximumNumberOfLines = 2

		let text = NSStackView(views: [title, sub])
		text.orientation = .vertical
		text.alignment = .leading
		text.spacing = 2
		return text
	}

	func buildBar() -> NSView {
		cancelButton.target = self
		cancelButton.action = #selector(cancel)
		cancelButton.keyEquivalent = "\u{1b}"
		cancelButton.controlSize = .large
		saveButton.target = self
		saveButton.action = #selector(save)
		saveButton.keyEquivalent = "\r"
		saveButton.keyEquivalentModifierMask = .command
		saveButton.bezelStyle = .rounded
		saveButton.controlSize = .large
		message.font = NSFont.systemFont(ofSize: 11)
		message.textColor = .secondaryLabelColor
		message.maximumNumberOfLines = 2
		message.setContentHuggingPriority(.defaultLow, for: .horizontal)
		message.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
		message.stringValue = t("Cmd+Return saves, Esc cancels.", "Cmd+Return speichert, Esc bricht ab.")
		let bar = NSStackView(views: [message, cancelButton, saveButton])
		bar.orientation = .horizontal
		bar.alignment = .centerY
		bar.spacing = 10
		return bar
	}

	func label(_ text: String, size: CGFloat, weight: NSFont.Weight = .regular, color: NSColor = .labelColor, wraps: Bool = true) -> NSTextField {
		let field = wraps ? NSTextField(wrappingLabelWithString: text) : NSTextField(labelWithString: text)
		field.font = NSFont.systemFont(ofSize: size, weight: weight)
		field.textColor = color
		field.alignment = .left
		return field
	}

	func stack(_ views: [NSView], _ orientation: NSUserInterfaceLayoutOrientation, spacing: CGFloat) -> NSStackView {
		let s = NSStackView(views: views)
		s.orientation = orientation
		s.alignment = orientation == .vertical ? .leading : .centerY
		s.spacing = spacing
		return s
	}

	func spacer() -> NSView {
		let v = NSView()
		v.setContentHuggingPriority(NSLayoutConstraint.Priority(1), for: .horizontal)
		return v
	}

	func separator() -> NSView {
		let line = NSBox()
		line.boxType = .separator
		return line
	}

	func card(for guide: Guide, index: Int, rows: [Row]) -> NSView {
		let host = guide.url.host ?? guide.url.absoluteString
		let title = label(t("Create the key on \(host)", "Schlüssel anlegen auf \(host)"), size: 14, weight: .semibold, wraps: false)
		title.lineBreakMode = .byTruncatingMiddle
		title.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
		let open = NSButton(title: t("Open page", "Seite öffnen"), image: symbol("arrow.up.right.square", "")!, target: self, action: #selector(openPageAction(_:)))
		open.imagePosition = .imageTrailing
		open.bezelStyle = .rounded
		open.tag = index
		open.toolTip = guide.url.absoluteString
		open.setAccessibilityLabel(t("Open page: \(host)", "Seite öffnen: \(host)"))
		let head = stack([title, spacer(), open], .horizontal, spacing: 8)

		let intro = label(t("The page opens in your browser at start. Do this there:", "Die Seite öffnet sich beim Start im Browser. Dort so vorgehen:"), size: 12, color: .secondaryLabelColor)
		var stepViews: [NSView] = []
		for (i, step) in guide.steps.enumerated() {
			let number = label("\(i + 1).", size: 13, weight: .semibold, color: .secondaryLabelColor, wraps: false)
			number.font = NSFont.monospacedDigitSystemFont(ofSize: 13, weight: .semibold)
			number.alignment = .right
			number.translatesAutoresizingMaskIntoConstraints = false
			number.widthAnchor.constraint(equalToConstant: 22).isActive = true
			let text = label(step, size: 13)
			text.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
			let line = stack([number, text], .horizontal, spacing: 6)
			line.alignment = .firstBaseline
			line.setAccessibilityElement(true)
			line.setAccessibilityLabel(t("Step \(i + 1): \(step)", "Schritt \(i + 1): \(step)"))
			stepViews.append(line)
		}
		let steps = stack(stepViews, .vertical, spacing: 6)
		for v in stepViews { v.widthAnchor.constraint(equalTo: steps.widthAnchor).isActive = true }

		var parts: [NSView] = [head, intro, steps]
		for row in rows {
			parts.append(separator())
			parts.append(keyBlock(for: row))
		}
		let block = stack(parts, .vertical, spacing: 12)
		block.setCustomSpacing(4, after: head)
		block.setCustomSpacing(8, after: intro)
		block.translatesAutoresizingMaskIntoConstraints = false
		for part in parts { part.widthAnchor.constraint(equalTo: block.widthAnchor).isActive = true }

		let card = Card()
		card.addSubview(block)
		NSLayoutConstraint.activate([
			block.topAnchor.constraint(equalTo: card.topAnchor, constant: 14),
			block.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -16),
			block.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 16),
			block.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -16),
		])
		return card
	}

	func keyBlock(for row: Row) -> NSView {
		let caption = label(t("Key name", "Schlüsselname"), size: 11, weight: .medium, color: .secondaryLabelColor, wraps: false)
		let name = NSTextField(string: row.entry.name)
		name.isEditable = false
		name.isSelectable = true
		name.bezelStyle = .roundedBezel
		name.font = NSFont.monospacedSystemFont(ofSize: 13, weight: .semibold)
		name.lineBreakMode = .byTruncatingMiddle
		name.setContentHuggingPriority(.defaultLow, for: .horizontal)
		name.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
		name.setAccessibilityLabel(t("Key name", "Schlüsselname"))
		row.copy.image = symbol("doc.on.doc", "")
		row.copy.imagePosition = .imageLeading
		row.copy.bezelStyle = .rounded
		row.copy.target = self
		row.copy.action = #selector(copyName(_:))
		row.copy.tag = rows.firstIndex { $0 === row } ?? 0
		row.copy.toolTip = t("Copy the key name, e.g. as token name on the page", "Schlüsselname in die Zwischenablage, z. B. als Token-Name auf der Seite")
		row.copy.setAccessibilityLabel(t("Copy key name \(row.entry.name)", "Schlüsselname \(row.entry.name) kopieren"))
		row.chip.set(row.chipText, row.chipTone)
		let nameLine = stack([name, row.copy, row.chip], .horizontal, spacing: 8)

		let hint = label(row.hint, size: 12, weight: .medium)
		row.field.placeholderString = t("Paste value", "Wert einfügen")
		row.field.delegate = self
		row.field.isEnabled = row.active
		row.field.controlSize = .large
		row.field.setContentHuggingPriority(.defaultLow, for: .horizontal)
		row.field.setAccessibilityLabel(t("Value for \(row.entry.name), \(row.chipText)", "Wert für \(row.entry.name), \(row.chipText)"))
		row.field.setAccessibilityHelp(row.hint)
		row.count.font = NSFont.monospacedDigitSystemFont(ofSize: 11, weight: .regular)
		row.count.textColor = .secondaryLabelColor
		row.count.alignment = .right
		row.count.translatesAutoresizingMaskIntoConstraints = false
		row.count.widthAnchor.constraint(greaterThanOrEqualToConstant: 72).isActive = true
		row.count.setAccessibilityLabel(t("Character count", "Zeichenzahl"))
		row.replace.target = self
		row.replace.action = #selector(refreshAction)
		var controls: [NSView] = [row.field, row.count]
		if case .existing = row.state { controls.append(row.replace) }
		let line = stack(controls, .horizontal, spacing: 10)
		line.distribution = .fill

		let parts: [NSView] = [caption, nameLine, hint, line]
		let block = stack(parts, .vertical, spacing: 6)
		block.setCustomSpacing(12, after: nameLine)
		for part in parts { part.widthAnchor.constraint(equalTo: block.widthAnchor).isActive = true }
		return block
	}

	@objc func openPageAction(_ sender: NSButton) {
		guard guides.indices.contains(sender.tag) else { return }
		openPage(guides[sender.tag].url)
	}

	@objc func copyName(_ sender: NSButton) {
		guard rows.indices.contains(sender.tag) else { return }
		let board = NSPasteboard.general
		board.clearContents()
		board.setString(rows[sender.tag].entry.name, forType: .string)
		sender.title = t("Copied", "Kopiert")
		sender.image = symbol("checkmark", "")
		NSAccessibility.post(element: sender, notification: .announcementRequested,
			userInfo: [.announcement: t("Key name copied", "Schlüsselname kopiert"), .priority: NSAccessibilityPriorityLevel.high.rawValue])
		DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) {
			sender.title = t("Copy", "Kopieren")
			sender.image = symbol("doc.on.doc", "")
		}
	}

	@objc func refreshAction() { refresh() }

	func refresh() {
		for row in rows {
			row.count.stringValue = t("\(row.field.stringValue.count) chars", "\(row.field.stringValue.count) Zeichen")
			row.replace.isEnabled = row.active
		}
		saveButton.isEnabled = rows.contains { $0.wantsSave }
	}

	func controlTextDidChange(_ obj: Notification) { refresh() }

	// Enter moves to the next field and never saves.
	func control(_ control: NSControl, textView: NSTextView, doCommandBy selector: Selector) -> Bool {
		guard selector == #selector(NSResponder.insertNewline(_:)) else { return false }
		let active = rows.filter { $0.active }
		if let i = active.firstIndex(where: { $0.field === control }), i + 1 < active.count {
			window.makeFirstResponder(active[i + 1].field)
		}
		return true
	}

	@objc func save() {
		guard saveButton.isEnabled else { return }
		setLocked(true)
		var storedValues: [String] = []
		var anyFailed = false
		for row in rows where row.wantsSave {
			let value = trimmed(row.field.stringValue)
			let reason: String? = keychain.lookup(row.entry.name) != row.state
				? "state changed"
				: keychain.store(name: row.entry.name, account: accountFor(row.state), value: value)
			if let reason = reason {
				outcomes[row.entry.name] = .failed(reason)
				row.chip.set(t("Error: \(reason)", "Fehler: \(reason)"), .error)
				anyFailed = true
			} else {
				outcomes[row.entry.name] = .stored
				storedValues.append(value)
				row.done = true
				row.field.stringValue = ""
				row.chip.set(t("stored", "gespeichert"), .ok)
			}
		}
		clearPasteboard(ifEqualTo: storedValues)
		setLocked(false)
		refresh()
		if anyFailed {
			message.stringValue = t("Not everything was stored. Check the row, save again or cancel.", "Nicht alles gespeichert. Zeile prüfen, erneut speichern oder abbrechen.")
			return
		}
		finish()
	}

	// Only when exactly one stored value is on the pasteboard; anything else stays untouched.
	func clearPasteboard(ifEqualTo values: [String]) {
		let board = NSPasteboard.general
		guard let current = board.string(forType: .string) else { return }
		if values.contains(where: { $0 == current || $0 == trimmed(current) }) { board.clearContents() }
	}

	func setLocked(_ locked: Bool) {
		for row in rows {
			row.field.isEnabled = !locked && row.active
			row.replace.isEnabled = !locked && row.active
		}
		cancelButton.isEnabled = !locked
		if locked { saveButton.isEnabled = false }
	}

	@objc func cancel() { finish() }

	func windowShouldClose(_ sender: NSWindow) -> Bool {
		finish()
		return false
	}

	func finish() {
		exit(report(entries, outcomes))
	}
}

// MARK: entry point

var names: [Entry] = []
var guides: [Guide] = []
var keychainPath: String?
var stdinValues = false
var seen = Set<String>()
var args = Array(CommandLine.arguments.dropFirst())
var pending: [(name: String, note: String)] = []
var pendingURL: URL?
var pendingSteps: [String]?
let guideMissing = "every NAME needs --url and --steps"
let guideOrder = "--url and --steps follow the names they belong to"

func closeGroup() {
	guard let url = pendingURL, let steps = pendingSteps else { fail(guideMissing) }
	guides.append(Guide(url: url, steps: steps))
	names += pending.map { Entry(name: $0.name, note: $0.note, guide: guides.count - 1) }
	pending = []
	pendingURL = nil
	pendingSteps = nil
}

while !args.isEmpty {
	let arg = args.removeFirst()
	switch arg {
	case "--keychain":
		guard let path = args.first else { fail("--keychain needs a path") }
		args.removeFirst()
		keychainPath = path
	case "--stdin-values":
		stdinValues = true
	case "--url", "--steps":
		guard let value = args.first, !value.hasPrefix("--") else { fail("\(arg) needs a value") }
		args.removeFirst()
		guard !pending.isEmpty else { fail(guideOrder) }
		if arg == "--url" {
			guard pendingURL == nil else { fail(guideOrder) }
			guard let url = validURL(value) else { fail("invalid url") }
			pendingURL = url
		} else {
			guard pendingSteps == nil else { fail(guideOrder) }
			let steps = parseSteps(value)
			guard !steps.isEmpty else { fail("--steps needs at least one step") }
			guard steps.count <= maxSteps else { fail("--steps takes at most \(maxSteps) steps") }
			pendingSteps = steps
		}
	default:
		let parts = arg.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
		let name = String(parts[0])
		guard validName(name) else { fail("invalid name") }
		guard seen.insert(name).inserted else { fail("duplicate name") }
		if pendingURL != nil && pendingSteps != nil { closeGroup() } else if pendingURL != nil || pendingSteps != nil { fail(guideMissing) }
		pending.append((name, parts.count > 1 ? trimmed(cleanText(String(parts[1]), limit: maxNote)) : ""))
	}
}

guard !pending.isEmpty else { fail("usage: KeyIntake NAME[=label] … --url <link> --steps \"<step> | …\"") }
closeGroup()

if stdinValues != (keychainPath != nil) { fail("--stdin-values and --keychain only work together") }

func fileIdentity(_ path: String) -> String? {
	var st = stat()
	guard stat(path, &st) == 0 else { return nil }
	return "\(st.st_dev):\(st.st_ino)"
}

if let path = keychainPath {
	guard path.hasPrefix("/") else { fail("test mode needs an absolute keychain path") }
	guard FileManager.default.fileExists(atPath: path) else { fail("keychain file not found") }
}

// Test mode only: stand-in for /usr/bin/security and an injected lookup status. The normal run ignores both.
guard let keychain = Keychain(
	path: keychainPath,
	securityPath: stdinValues ? (env["KEY_INTAKE_SECURITY"] ?? "/usr/bin/security") : "/usr/bin/security",
	injectedLookupStatus: stdinValues ? env["KEY_INTAKE_TEST_LOOKUP_STATUS"].flatMap { Int32($0) } : nil
) else { fail("keychain not available") }

if stdinValues {
	// Judged after opening: the path SecKeychainOpen reports and the device/inode count, not the spelling the caller used.
	let home = NSHomeDirectory()
	let loginPath = home + "/Library/Keychains/login.keychain-db"
	let candidates = [keychain.path, keychainPath ?? ""]
	let loginId = fileIdentity(loginPath)
	for candidate in candidates where !candidate.isEmpty {
		let resolved = URL(fileURLWithPath: candidate).resolvingSymlinksInPath().path
		if resolved == URL(fileURLWithPath: loginPath).resolvingSymlinksInPath().path || resolved.hasPrefix(home + "/Library/Keychains/")
			|| (loginId != nil && fileIdentity(candidate) == loginId) {
			fail("test mode refuses the login keychain")
		}
	}
}

let states = names.map { keychain.lookup($0.name) }

if stdinValues {
	exit(runTestMode(entries: names, states: states, keychain: keychain))
}

if states.allSatisfy({ state in
	switch state {
	case .ambiguous, .error: return true
	default: return false
	}
}) {
	var outcomes: [String: Outcome] = [:]
	for (e, state) in zip(names, states) { outcomes[e.name] = .failed(state == .error ? "lookup error" : "ambiguous") }
	exit(report(names, outcomes))
}

let app = NSApplication.shared
app.setActivationPolicy(.regular)
let controller = Controller(entries: names, guides: guides, states: states, keychain: keychain)
app.delegate = controller
app.run()
