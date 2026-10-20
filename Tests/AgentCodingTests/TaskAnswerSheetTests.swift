import AppKit
import SwiftUI
import Testing
@testable import bromure_ac

/// Board: a coding task's question opened in an alert — a sliver of the
/// question and a one-line field to answer in. It's now a sheet: the whole
/// question (markdown, selectable, scrolling) above a multi-line editor.
@Suite("Coding tasks: the answer sheet has room to read and write", .serialized)
@MainActor
struct TaskAnswerSheetTests {
    private func question() -> String {
        """
        Before I change the retry policy I need two decisions:

        - Should a 429 from the upstream count toward the circuit breaker, or only 5xx?
        - The current backoff caps at 30 s. Keep it, or raise it to 120 s for the batch jobs?

        Context: the batch importer retries 40 times in a burst and trips the breaker for every \
        other client. I can make the breaker per-client instead, which is a larger change.
        """
    }

    private func task() -> CodingTask {
        var t = CodingTask(title: "Retry policy for the importer", profileID: UUID(), tool: .claude)
        t.assignment = TaskAssignment(kind: .session, id: UUID(), label: "@importer")
        t.pendingQuestion = question()
        return t
    }

    @Test("the sheet is a roomy window with a multi-line editor")
    func roomySheet() throws {
        _ = NSApplication.shared
        var sent: [String] = []
        var reply = ""
        let binding = Binding(get: { reply }, set: { reply = $0 })
        let host = NSHostingView(rootView: TaskAnswerSheet(task: task(), reply: binding,
                                                           onSend: { sent.append($0) }, onCancel: {}))
        let size = host.fittingSize
        #expect(size.width >= 560, "sheet \(size.width) wide")
        #expect(size.height >= 480, "sheet \(size.height) tall")

        host.frame = NSRect(origin: .zero, size: size)
        host.layoutSubtreeIfNeeded()
        let editors = textViews(in: host).filter(\.isEditable)
        let editor = try #require(editors.first)
        #expect(editor.frame.height >= 120, "answer editor \(editor.frame.height) tall")
        #expect(editor.frame.width >= 480, "answer editor \(editor.frame.width) wide")

        if let out = ProcessInfo.processInfo.environment["TASK_ANSWER_SHOT"],
           let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) {
            host.cacheDisplay(in: host.bounds, to: rep)
            try rep.representation(using: .png, properties: [:])?.write(to: URL(fileURLWithPath: out))
        }
        #expect(sent.isEmpty)
    }

    private func textViews(in view: NSView) -> [NSTextView] {
        ((view as? NSTextView).map { [$0] } ?? []) + view.subviews.flatMap(textViews(in:))
    }
}
