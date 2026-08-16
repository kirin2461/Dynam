#!/usr/bin/env swift
// Generate Dynam.icns via CoreGraphics + ImageIO (no AppKit, works headless).
// Output: scripts/out/Dynam.icns

import Foundation
import CoreGraphics
import CoreText
import ImageIO
import UniformTypeIdentifiers

let outDir   = "scripts/out/icon.iconset"
let icnsPath = "scripts/out/Dynam.icns"
try? FileManager.default.removeItem(atPath: outDir)
try FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true)

func drawIconPNG(size: Int, to path: String) throws {
    let s = CGFloat(size)
    let cs = CGColorSpaceCreateDeviceRGB()
    guard let ctx = CGContext(
        data: nil, width: size, height: size,
        bitsPerComponent: 8, bytesPerRow: 0, space: cs,
        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else {
        fatalError("CGContext create failed at size \(size)")
    }

    // Rounded background with linear gradient
    let radius = s * 0.22
    let rect = CGRect(x: 0, y: 0, width: s, height: s)
    let roundedPath = CGPath(roundedRect: rect, cornerWidth: radius, cornerHeight: radius, transform: nil)

    ctx.saveGState()
    ctx.addPath(roundedPath)
    ctx.clip()

    let colors = [
        CGColor(red: 0.29, green: 0.27, blue: 0.55, alpha: 1.0),
        CGColor(red: 0.15, green: 0.13, blue: 0.32, alpha: 1.0),
    ] as CFArray
    let grad = CGGradient(colorsSpace: cs, colors: colors, locations: [0.0, 1.0])!
    ctx.drawLinearGradient(grad,
        start: CGPoint(x: 0, y: s),
        end:   CGPoint(x: s, y: 0),
        options: [])

    // Subtle ring
    ctx.setStrokeColor(CGColor(red: 1, green: 1, blue: 1, alpha: 0.08))
    ctx.setLineWidth(s * 0.012)
    ctx.strokeEllipse(in: CGRect(x: s * 0.12, y: s * 0.12, width: s * 0.76, height: s * 0.76))

    // Letter "D" via CoreText (CGContext-friendly; no AppKit needed)
    let fontSize = s * 0.62
    let font = CTFontCreateWithName("HelveticaNeue-Bold" as CFString, fontSize, nil)
    // CoreText uses CFString attribute keys, not NSAttributedString.Key —
    // foregroundColor must be the CT key, not the AppKit one.
    let attrs: [CFString: Any] = [
        kCTFontAttributeName:            font,
        kCTForegroundColorAttributeName: CGColor(red: 1, green: 1, blue: 1, alpha: 1),
    ]
    let attrStr = CFAttributedStringCreate(nil, "D" as CFString, attrs as CFDictionary)!
    let line = CTLineCreateWithAttributedString(attrStr)
    let bounds = CTLineGetBoundsWithOptions(line, .useGlyphPathBounds)

    ctx.textPosition = CGPoint(
        x: (s - bounds.width)  / 2 - bounds.minX,
        y: (s - bounds.height) / 2 - bounds.minY
    )
    CTLineDraw(line, ctx)

    ctx.restoreGState()

    guard let cgImage = ctx.makeImage() else { fatalError("makeImage failed") }
    let url = URL(fileURLWithPath: path) as CFURL
    let pngType = UTType.png.identifier as CFString
    guard let dest = CGImageDestinationCreateWithURL(url, pngType, 1, nil) else {
        fatalError("dest create failed")
    }
    CGImageDestinationAddImage(dest, cgImage, nil)
    guard CGImageDestinationFinalize(dest) else {
        fatalError("dest finalize failed")
    }
}

let sizes: [(String, Int)] = [
    ("icon_16x16.png",        16),
    ("icon_16x16@2x.png",     32),
    ("icon_32x32.png",        32),
    ("icon_32x32@2x.png",     64),
    ("icon_128x128.png",     128),
    ("icon_128x128@2x.png",  256),
    ("icon_256x256.png",     256),
    ("icon_256x256@2x.png",  512),
    ("icon_512x512.png",     512),
    ("icon_512x512@2x.png", 1024),
]

for (name, px) in sizes {
    try drawIconPNG(size: px, to: "\(outDir)/\(name)")
    print("wrote \(outDir)/\(name)")
}

let p = Process()
p.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
p.arguments = ["-c", "icns", "-o", icnsPath, outDir]
try p.run()
p.waitUntilExit()
print("wrote \(icnsPath)")
