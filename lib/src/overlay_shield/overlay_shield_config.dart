/// Configuration for [OverlayShield].
class OverlayShieldConfig {
  /// Creates an [OverlayShieldConfig] with the given options.
  const OverlayShieldConfig({
    this.filterTouchesWhenObscured = true,
    this.detectSystemOverlays = false,
    this.allowedOverlayPackages = const [],
  });

  /// Whether to reject touches when the app window is obscured by an overlay.
  final bool filterTouchesWhenObscured;

  /// Whether to detect system-level overlays (e.g. status bar overlays).
  final bool detectSystemOverlays;

  /// Package names of overlays that should be allowed (not flagged).
  final List<String> allowedOverlayPackages;

  /// Creates a copy with the given fields replaced.
  OverlayShieldConfig copyWith({
    bool? filterTouchesWhenObscured,
    bool? detectSystemOverlays,
    List<String>? allowedOverlayPackages,
  }) {
    return OverlayShieldConfig(
      filterTouchesWhenObscured: filterTouchesWhenObscured ?? this.filterTouchesWhenObscured,
      detectSystemOverlays: detectSystemOverlays ?? this.detectSystemOverlays,
      allowedOverlayPackages: allowedOverlayPackages ?? this.allowedOverlayPackages,
    );
  }
}
