import Foundation

/// What the iOS collector makes of what it read: pure functions with no
/// Apple-only framework in them, so they compile and can be tested on any
/// Swift toolchain - the counterpart of
/// Android's ProbeReads.kt. The collector reads Mach-O headers, files and
/// Core Location; these decide what the reads mean.
enum ProbeReads {

    // MARK: - App-code coverage

    /// The largest __TEXT segment read from disk for one comparison.
    static let maxTextSegment: UInt64 = 64 * 1024 * 1024
    /// Images not compared that are named, at most (the server's list bound).
    static let maxNamedImages = 64

    /// Where an image's __text lies, as its load commands state it.
    struct TextSpan: Equatable {
        /// The whole __TEXT segment: its file offset and size, and where it
        /// is mapped before the image's slide.
        let segmentFileOffset: Int
        let segmentSize: Int
        let segmentVMAddress: UInt64
        /// The __text section inside that segment: only this range is scored.
        let textOffsetInSegment: Int
        let textSize: Int
    }

    /// Why one app image's __text was not compared, and how many __text bytes
    /// that leaves out: 0 when its size could not be read.
    struct CoverageProblem: Error, Equatable {
        let reason: String
        let textSize: Int
    }

    /// The __text section of a __TEXT segment, or why it cannot be compared.
    /// The section is checked before the segment's budget is applied, so an
    /// image over the budget is skipped with its size rather than dropped
    /// unseen; the header's unsigned values are checked before any becomes an
    /// Int. `section` is nil when the segment names no __text.
    static func textSpan(
        segmentFileOffset fileOffset: UInt64,
        segmentFileSize fileSize: UInt64,
        segmentVMAddress: UInt64,
        section: (offset: UInt64, size: UInt64)?
    ) -> Result<TextSpan, CoverageProblem> {
        guard let section = section else {
            return .failure(CoverageProblem(reason: "no __text section in __TEXT", textSize: 0))
        }
        let size = section.size
        guard size > 0 else {
            return .failure(CoverageProblem(reason: "an empty __text section", textSize: 0))
        }
        guard section.offset >= fileOffset, size <= fileSize,
              section.offset - fileOffset <= fileSize - size else {
            return .failure(CoverageProblem(reason: "__text lies outside its __TEXT segment", textSize: 0))
        }
        guard fileSize <= maxTextSegment else {
            return .failure(CoverageProblem(
                reason: "__TEXT of \(fileSize) bytes is over the 64 MiB budget",
                textSize: size <= 1 << 40 ? Int(size) : 0))
        }
        return .success(TextSpan(
            segmentFileOffset: Int(clamping: fileOffset),
            segmentSize: Int(fileSize),
            segmentVMAddress: segmentVMAddress,
            textOffsetInSegment: Int(section.offset - fileOffset),
            textSize: Int(size)
        ))
    }

    /// Why a read of `wanted` bytes is not the whole of them, or nil: a short
    /// read is unreadable, never a comparison of part.
    static func readProblem(got: Int, wanted: Int) -> String? {
        return got == wanted ? nil : "unreadable: \(got) of \(wanted) bytes read"
    }

    /// How one app image's comparison ended.
    enum ImageOutcome: Equatable {
        /// Compared: its __text bytes and how many differ, and the same for
        /// the whole __TEXT segment (telemetry).
        case compared(textBytes: Int, textDiffering: Int, segmentBytes: Int, segmentDiffering: Int)
        /// Its file could not be read in full.
        case unreadable(textBytes: Int, why: String)
        /// Not compared: no usable __text, a __TEXT over the budget, no live
        /// address. Its __text bytes when known, else 0.
        case skipped(textBytes: Int, why: String)
    }

    /// One image the loader mapped from the app's bundle.
    struct AppImage: Equatable {
        /// Its path in the bundle (bundleLabel).
        let path: String
        let isMainExecutable: Bool
        let outcome: ImageOutcome
    }

    /// An image's path in the bundle, as the report names it: at most 128
    /// characters, its end kept; "(bundle)" for the bundle itself.
    static func bundleLabel(imagePath: String, bundlePath: String) -> String {
        let inBundle = String(imagePath.dropFirst(bundlePath.count).drop(while: { $0 == "/" }))
        return inBundle.isEmpty ? "(bundle)" : String(inBundle.suffix(128))
    }

    /// The app bucket's figures from every bundle image's outcome (collector
    /// 5): every image expected, and each compared, unreadable or skipped,
    /// with its __text bytes; each one not compared named with why; complete
    /// only when every image was compared - the images decide, since one
    /// whose size could not be read adds no bytes. `checked` means the app
    /// bucket was genuinely compared: not one image, nothing measured.
    static func appCoverage(_ images: [AppImage], systemImagesUnreadable: Int) -> [String: Any] {
        var compared = 0, unreadable = 0, skipped = 0
        var expectedBytes = 0, comparedBytes = 0, unreadableBytes = 0, skippedBytes = 0
        var differing = 0, imagesDiffering = 0, segmentCompared = 0, segmentDiffering = 0
        var diffed: [String] = []
        var notCompared: [String: String] = [:]
        var mainCompared = false

        func name(_ image: AppImage, _ why: String) {
            if notCompared.count < maxNamedImages {
                notCompared[image.path] = String(why.prefix(160))
            }
        }

        for image in images {
            switch image.outcome {
            case let .compared(textBytes, textDiffering, segmentBytes, segmentDiff):
                compared += 1
                expectedBytes += textBytes
                comparedBytes += textBytes
                segmentCompared += segmentBytes
                segmentDiffering += segmentDiff
                if image.isMainExecutable { mainCompared = true }
                if textDiffering > 0 {
                    differing += textDiffering
                    imagesDiffering += 1
                    diffed.append(image.path.split(separator: "/").last.map(String.init) ?? image.path)
                }
            case let .unreadable(textBytes, why):
                unreadable += 1
                expectedBytes += textBytes
                unreadableBytes += textBytes
                name(image, why)
            case let .skipped(textBytes, why):
                skipped += 1
                expectedBytes += textBytes
                skippedBytes += textBytes
                name(image, why)
            }
        }

        var result: [String: Any] = [
            "checked": compared > 0,
            "app_compared_bytes": comparedBytes,
            "app_diff_bytes": differing,
            "app_libs_diff": imagesDiffering,
            "app_images_compared": compared,
            "system_images_unreadable": systemImagesUnreadable,
            "app_images_expected": images.count,
            "app_images_unreadable": unreadable,
            "app_images_skipped": skipped,
            "app_expected_bytes": expectedBytes,
            "app_unreadable_bytes": unreadableBytes,
            "app_skipped_bytes": skippedBytes,
            "app_complete": !images.isEmpty && compared == images.count,
            "main_executable_compared": mainCompared,
            // Telemetry only. Never scored until it has a hardware baseline.
            "app_segment_compared_bytes": segmentCompared,
            "app_segment_diff_bytes": segmentDiffering,
            "diffed_libs": diffed.joined(separator: ","),
        ]
        if !notCompared.isEmpty {
            result["app_images_not_compared"] = notCompared
        }
        return result
    }

    // MARK: - One location read per collection

    /// One fix as the collector captured it from Core Location.
    struct Fix: Equatable {
        let latitude: Double
        let longitude: Double
        /// Negative when unknown, as Core Location reports it.
        let horizontalAccuracy: Double
        let timestamp: Date
        /// From iOS 15, where the fix says; nil where it cannot.
        let simulatedBySoftware: Bool?
        let producedByAccessory: Bool?
    }

    /// One location read: the permission, the fix the phone already held -
    /// none without the permission - and its age when read.
    struct LocationRead: Equatable {
        let permission: String
        let fix: Fix?
        let ageSeconds: Int
    }

    static func read(permission: String, fix: Fix?, now: Date) -> LocationRead {
        let held = permission == "none" ? nil : fix
        let age = held.map { max(0, Int(now.timeIntervalSince($0.timestamp))) } ?? 0
        return LocationRead(permission: permission, fix: held, ageSeconds: age)
    }

    /// The collection's one location read: made on first use and never again,
    /// so the coordinates and the mock flag describe one fix. Each collection
    /// makes its own.
    final class LocationCapture {
        private let read: () -> LocationRead
        private var made: LocationRead?

        init(_ read: @escaping () -> LocationRead) {
            self.read = read
        }

        var value: LocationRead {
            if let made = made { return made }
            let fresh = self.read()
            made = fresh
            return fresh
        }
    }

    /// The last known location: the coordinates of the read's fix.
    static func location(_ read: LocationRead) -> [String: Any] {
        var result: [String: Any] = ["status": "ok", "permission": read.permission]
        guard let fix = read.fix else { return result }
        result["latitude"] = fix.latitude
        result["longitude"] = fix.longitude
        if fix.horizontalAccuracy >= 0 { result["accuracy_m"] = fix.horizontalAccuracy }
        result["age_seconds"] = read.ageSeconds
        result["fix_time"] = Int(fix.timestamp.timeIntervalSince1970)
        return result
    }

    /// Whether the read's fix was simulated by software or produced by an
    /// accessory: never its coordinates. Before iOS 15 the fix cannot say.
    static func mockLocation(_ read: LocationRead) -> [String: Any] {
        var result: [String: Any] = ["status": "ok", "permission": read.permission]
        guard let fix = read.fix else { return result }
        if let simulated = fix.simulatedBySoftware { result["mock"] = simulated }
        if let accessory = fix.producedByAccessory { result["accessory"] = accessory }
        result["age_seconds"] = read.ageSeconds
        result["fix_time"] = Int(fix.timestamp.timeIntervalSince1970)
        return result
    }

    /// Screen capture (collector 6): `recording` when a screen showing the
    /// app's window could be asked. With none - the app in the background, or
    /// before its first window - recording is not measured, never "no", and
    /// `recording_status` says why: `unavailable`, as on Android with no window
    /// to ask. The other screens attached are counted either way.
    static func screenCapture(captured: Bool?, otherScreens: Int) -> [String: Any] {
        var result: [String: Any] = ["status": "ok", "external_displays": max(0, otherScreens)]
        if let captured = captured {
            result["recording"] = captured
        } else {
            result["recording_status"] = "unavailable"
        }
        return result
    }
}
