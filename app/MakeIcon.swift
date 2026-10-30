// MakeIcon — draws the KeyIntake app icon into an .iconset folder (iconutil turns it into the .icns).
// usage: MakeIcon <output .iconset directory>

import AppKit

func color(_ hex: UInt32, _ alpha: CGFloat = 1) -> NSColor {
	NSColor(srgbRed: CGFloat((hex >> 16) & 0xff) / 255, green: CGFloat((hex >> 8) & 0xff) / 255, blue: CGFloat(hex & 0xff) / 255, alpha: alpha)
}

// Drawn on a 1024 grid, y up. The tile is 824 wide, as in Apple's icon template.
func draw() {
	let tile = NSBezierPath(roundedRect: NSRect(x: 100, y: 100, width: 824, height: 824), xRadius: 184, yRadius: 184)

	NSGraphicsContext.saveGraphicsState()
	let shadow = NSShadow()
	shadow.shadowOffset = NSSize(width: 0, height: -14)
	shadow.shadowBlurRadius = 30
	shadow.shadowColor = NSColor.black.withAlphaComponent(0.4)
	shadow.set()
	color(0x123a32).setFill()
	tile.fill()
	NSGraphicsContext.restoreGraphicsState()

	NSGraphicsContext.saveGraphicsState()
	tile.addClip()
	NSGradient(colors: [color(0x0b201c), color(0x236053), color(0x3a8a74)], atLocations: [0, 0.55, 1], colorSpace: .sRGB)?
		.draw(in: tile.bounds, angle: 90)
	NSGradient(colors: [NSColor.white.withAlphaComponent(0.22), NSColor.white.withAlphaComponent(0)], atLocations: [0, 1], colorSpace: .sRGB)?
		.draw(in: NSRect(x: 100, y: 512, width: 824, height: 412), angle: 270)
	NSGraphicsContext.restoreGraphicsState()

	let hairline = NSBezierPath(roundedRect: NSRect(x: 101, y: 101, width: 822, height: 822), xRadius: 183, yRadius: 183)
	hairline.lineWidth = 2
	NSColor.white.withAlphaComponent(0.16).setStroke()
	hairline.stroke()

	// Key: ring with an orange hole, shaft and two teeth, tilted 45° so it reads at 16 px.
	NSGraphicsContext.saveGraphicsState()
	let transform = NSAffineTransform()
	transform.translateX(by: 512, yBy: 512)
	transform.rotate(byDegrees: 45)
	transform.concat()

	let keyShadow = NSShadow()
	keyShadow.shadowOffset = NSSize(width: 0, height: -10)
	keyShadow.shadowBlurRadius = 22
	keyShadow.shadowColor = NSColor.black.withAlphaComponent(0.35)
	keyShadow.set()

	let ring = NSBezierPath()
	ring.windingRule = .evenOdd
	ring.append(NSBezierPath(ovalIn: NSRect(x: -330, y: -135, width: 270, height: 270)))
	ring.append(NSBezierPath(ovalIn: NSRect(x: -258, y: -63, width: 126, height: 126)))
	let shaft = NSBezierPath(roundedRect: NSRect(x: -100, y: -46, width: 440, height: 92), xRadius: 46, yRadius: 46)
	shaft.append(NSBezierPath(roundedRect: NSRect(x: 230, y: -150, width: 76, height: 130), xRadius: 22, yRadius: 22))
	shaft.append(NSBezierPath(roundedRect: NSRect(x: 130, y: -118, width: 70, height: 98), xRadius: 22, yRadius: 22))
	color(0xf4e7d9).setFill()
	ring.fill()
	shaft.fill()

	NSShadow().set()
	color(0xff6b30).setFill()
	NSBezierPath(ovalIn: NSRect(x: -230, y: -35, width: 70, height: 70)).fill()
	NSGraphicsContext.restoreGraphicsState()
}

func png(pixels: Int) -> Data? {
	guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels, bitsPerSample: 8,
		samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
		let context = NSGraphicsContext(bitmapImageRep: rep) else { return nil }
	NSGraphicsContext.saveGraphicsState()
	NSGraphicsContext.current = context
	context.imageInterpolation = .high
	let scale = NSAffineTransform()
	scale.scale(by: CGFloat(pixels) / 1024)
	scale.concat()
	draw()
	NSGraphicsContext.restoreGraphicsState()
	return rep.representation(using: .png, properties: [:])
}

guard CommandLine.arguments.count == 2 else {
	FileHandle.standardError.write(Data("usage: MakeIcon <output .iconset directory>\n".utf8))
	exit(2)
}
let dir = URL(fileURLWithPath: CommandLine.arguments[1])
try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

let sizes: [(String, Int)] = [
	("icon_16x16", 16), ("icon_16x16@2x", 32), ("icon_32x32", 32), ("icon_32x32@2x", 64),
	("icon_128x128", 128), ("icon_128x128@2x", 256), ("icon_256x256", 256), ("icon_256x256@2x", 512),
	("icon_512x512", 512), ("icon_512x512@2x", 1024),
]
for (name, pixels) in sizes {
	guard let data = png(pixels: pixels) else {
		FileHandle.standardError.write(Data("render failed\n".utf8))
		exit(2)
	}
	try data.write(to: dir.appendingPathComponent(name + ".png"))
}
