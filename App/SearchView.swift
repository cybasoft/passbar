import SwiftUI
import PassboltKit

struct SearchView: View {
    @ObservedObject var model: AppModel
    let actions: AppActions
    @FocusState private var focused: Bool
    @State private var highlighted = 0

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Search Passbolt...", text: $model.query)
                    .textFieldStyle(.plain)
                    .focused($focused)
                    .onSubmit { open(highlighted) }
                    .onKeyPress(.downArrow) { move(1); return .handled }
                    .onKeyPress(.upArrow) { move(-1); return .handled }
                    .onKeyPress(.escape) { actions.close(); return .handled }
            }
            .padding(10)
            Divider()
            if model.isLoading { ProgressView().frame(maxHeight: .infinity) }
            else if model.results.isEmpty {
                Text(model.query.isEmpty ? "No resources" : "No matches")
                    .foregroundStyle(.secondary).frame(maxHeight: .infinity)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(Array(model.results.enumerated()), id: \.element.id) { i, r in
                                Row(resource: r, selected: i == highlighted)
                                    .id(r.id)
                                    .onTapGesture { open(i) }
                            }
                        }
                    }
                    .onChange(of: highlighted) { _, i in
                        if model.results.indices.contains(i) { proxy.scrollTo(model.results[i].id) }
                    }
                }
            }
        }
        .onAppear { focused = true; model.touch() }
        .onChange(of: model.query) { _, _ in highlighted = 0; model.touch() }
    }

    private func move(_ d: Int) {
        guard !model.results.isEmpty else { return }
        highlighted = min(max(highlighted + d, 0), model.results.count - 1)
        model.touch()
    }

    private func open(_ i: Int) {
        guard model.results.indices.contains(i) else { return }
        let r = model.results[i]
        Task { await model.select(r) }
    }

    struct Row: View {
        let resource: PassboltResource
        let selected: Bool
        var body: some View {
            VStack(alignment: .leading, spacing: 1) {
                Text(resource.name).lineLimit(1)
                if !resource.username.isEmpty {
                    Text(resource.username).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 12).padding(.vertical, 6)
            .background(selected ? Color.accentColor.opacity(0.25) : .clear)
            .contentShape(Rectangle())
            .accessibilityElement(children: .combine)
        }
    }
}
