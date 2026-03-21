import 'package:flutter/material.dart';

/// Screenshot Watermark Shield — Overlay invisible/semi-visible watermarks.
class WatermarkShield {
  WatermarkShield._();
  /// The singleton [WatermarkShield] instance.
  static final WatermarkShield instance = WatermarkShield._();

  String? _watermarkText;
  double _opacity = 0.03;
  double _fontSize = 14.0;
  double _angle = -30.0;

  /// Configures the watermark [text], [opacity], [fontSize], and [angle].
  void configure({required String text, double opacity = 0.03, double fontSize = 14.0, double angle = -30.0}) {
    _watermarkText = text;
    _opacity = opacity;
    _fontSize = fontSize;
    _angle = angle;
  }

  /// The current watermark text, or `null` if not configured.
  String? get watermarkText => _watermarkText;

  /// The watermark opacity (0.0 = invisible, 1.0 = fully opaque).
  double get opacity => _opacity;

  /// The watermark font size in logical pixels.
  double get fontSize => _fontSize;

  /// The watermark rotation angle in degrees.
  double get angle => _angle;

  /// Resets all watermark settings to their defaults.
  void reset() { _watermarkText = null; _opacity = 0.03; _fontSize = 14.0; _angle = -30.0; }
}

/// Widget that overlays a repeating watermark pattern on its child.
class WatermarkOverlay extends StatelessWidget {
  /// Creates a [WatermarkOverlay] with the given [text] and styling options.
  const WatermarkOverlay({
    super.key,
    required this.child,
    required this.text,
    this.opacity = 0.03,
    this.fontSize = 14.0,
    this.angle = -30.0,
    this.color = Colors.black,
  });

  /// The child widget to overlay the watermark on.
  final Widget child;

  /// The watermark text repeated across the overlay.
  final String text;

  /// Opacity of the watermark layer (default: 0.03).
  final double opacity;

  /// Font size of the watermark text in logical pixels.
  final double fontSize;

  /// Rotation angle of the watermark in degrees.
  final double angle;

  /// Color of the watermark text.
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        child,
        Positioned.fill(
          child: IgnorePointer(
            child: Opacity(
              opacity: opacity,
              child: Transform.rotate(
                angle: angle * 3.14159 / 180,
                child: Wrap(
                  spacing: 40,
                  runSpacing: 30,
                  children: List.generate(50, (_) => Text(
                    text,
                    style: TextStyle(fontSize: fontSize, color: color, fontWeight: FontWeight.w300, decoration: TextDecoration.none),
                  )),
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }
}
