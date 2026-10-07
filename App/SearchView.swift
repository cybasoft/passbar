import SwiftUI
import PassBarKit

struct SearchView: View {
    @ObservedObject var model: AppModel
    let actions: AppActions
    @FocusState private var focused: Bool
    @State private var highlighted = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            searchField
            resultsCard
        }
        .padding(.horizontal, 16).padding(.top, 14).padding(.bottom, 10)
        .onAppear { focused = true; model.touch() }
        .onChange(of: model.query) { _, _ in highlighted = 0; model.touch() }
    }

    private var header: some View {
        HStack(spacing: 14) {
            Text("PassBar").font(.system(size: 18, weight: .bold))
            Spacer()
            Button { model.isCreating = true } label: { Image(systemName: "plus").font(.system(size: 18)) }
                .help("New credential").accessibilityLabel("New credential")
            Button { actions.openServer() } label: { Image(systemName: "macwindow").font(.system(size: 18)) }
                .help("Open Passbolt").accessibilityLabel("Open Passbolt in browser")
        }
        .buttonStyle(.plain)
    }

    private var searchField: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass").font(.system(size: 16)).foregroundStyle(.secondary)
            TextField("Search", text: $model.query)
                .textFieldStyle(.plain).font(.system(size: 16))
                .focused($focused)
                .onSubmit { open(highlighted) }
                .onKeyPress(.downArrow) { move(1); return .handled }
                .onKeyPress(.upArrow) { move(-1); return .handled }
                .onKeyPress(.escape) { actions.close(); return .handled }
        }
        .padding(.horizontal, 12).padding(.vertical, 9)
        .background(RoundedRectangle(cornerRadius: 14).fill(Color.primary.opacity(0.1)))
        .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(Color.accentColor.opacity(focused ? 0.9 : 0), lineWidth: 2.5))
    }

    private var resultsCard: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 16).fill(Color.primary.opacity(0.06))
            if model.isLoading { ProgressView() }
            else if model.results.isEmpty {
                Text(model.query.isEmpty ? "No resources" : "No matches").foregroundStyle(.secondary)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(Array(model.results.enumerated()), id: \.element.id) { i, r in
                                Row(resource: r, selected: i == highlighted, showDivider: i < model.results.count - 1)
                                    .id(r.id)
                                    .onTapGesture { open(i) }
                            }
                        }
                        .padding(.vertical, 4)
                    }
                    .onChange(of: highlighted) { _, i in
                        if model.results.indices.contains(i) { proxy.scrollTo(model.results[i].id) }
                    }
                }
            }
        }
        .frame(maxHeight: .infinity)
        .clipShape(RoundedRectangle(cornerRadius: 16))
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
        let showDivider: Bool
        var body: some View {
            HStack(spacing: 12) {
                ResourceIcon(name: resource.name)
                VStack(alignment: .leading, spacing: 2) {
                    Text(resource.name).font(.system(size: 16, weight: .semibold)).lineLimit(1)
                    if !resource.username.isEmpty {
                        Text(resource.username).font(.system(size: 13)).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
                Spacer(minLength: 4)
                Image(systemName: "chevron.right").font(.system(size: 13, weight: .semibold)).foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
            .background(selected ? Color.accentColor.opacity(0.22) : .clear)
            .overlay(alignment: .bottom) { if showDivider { Divider().padding(.leading, 64) } }
            .contentShape(Rectangle())
            .accessibilityElement(children: .combine)
        }
    }
}

/// Letter tile with a stable colour per name (no network icon lookups).
struct ResourceIcon: View {
    let name: String
    private static let palette: [Color] = [
        Color(white: 0.62), Color(red: 0.86, green: 0.30, blue: 0.55), Color(red: 0.16, green: 0.55, blue: 0.62),
        Color(red: 0.93, green: 0.55, blue: 0.20), Color(red: 0.27, green: 0.47, blue: 0.86),
        Color(red: 0.30, green: 0.68, blue: 0.40), Color(red: 0.55, green: 0.38, blue: 0.82),
    ]
    var body: some View {
        let hash = name.unicodeScalars.reduce(0) { ($0 &* 31 &+ Int($1.value)) % 1_000_003 }
        ZStack {
            RoundedRectangle(cornerRadius: 10).fill(Self.palette[hash % Self.palette.count])
            Text(name.first.map { String($0).uppercased() } ?? "?")
                .font(.system(size: 22, weight: .medium)).foregroundStyle(.white)
        }
        .frame(width: 40, height: 40)
        .accessibilityHidden(true)
    }
}
