// Copyright 2026 Layergram
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:math' as math;
import 'package:flutter/material.dart';

class LayergramBackground extends StatefulWidget {
  final Widget child;

  const LayergramBackground({
    super.key,
    required this.child,
  });

  @override
  State<LayergramBackground> createState() => _LayergramBackgroundState();
}

class _LayergramBackgroundState extends State<LayergramBackground> {
  late final _SecurityLayerLayout _layout;

  @override
  void initState() {
    super.initState();
    // Decorative randomness is generated once per app session and is never
    // used by, or sourced from, Layergram's cryptographic entropy paths.
    _layout = _SecurityLayerLayout.random(math.Random());
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final dark = theme.brightness == Brightness.dark;
    final painter = _SecurityLayersPainter(
      isDark: dark,
      primaryColor: theme.colorScheme.primary,
      layout: _layout,
    );

    // Tech/Security Palette
    // Dark: Deep slate/blue
    // Light: Crisp white/cyan tint
    final bgColor = dark ? const Color(0xFF050F16) : const Color(0xFFF2F8FA);

    return Stack(
      children: [
        // 1. Solid Base
        Positioned.fill(
          child: RepaintBoundary(
            child: ColoredBox(color: bgColor),
          ),
        ),

        // 2. Static session-randomized security layers
        Positioned.fill(
          child: RepaintBoundary(
            child: CustomPaint(painter: painter),
          ),
        ),

        // 3. Main Content
        Positioned.fill(child: RepaintBoundary(child: widget.child)),
      ],
    );
  }
}

class _SecurityLayerLayout {
  final double firstX;
  final double firstY;
  final double firstSize;
  final double firstRotation;
  final double secondX;
  final double secondY;
  final double secondSize;
  final double secondRotation;
  final double thirdX;
  final double thirdY;
  final double thirdSize;
  final double thirdRotation;
  final double gridOffsetX;
  final double gridOffsetY;

  const _SecurityLayerLayout({
    required this.firstX,
    required this.firstY,
    required this.firstSize,
    required this.firstRotation,
    required this.secondX,
    required this.secondY,
    required this.secondSize,
    required this.secondRotation,
    required this.thirdX,
    required this.thirdY,
    required this.thirdSize,
    required this.thirdRotation,
    required this.gridOffsetX,
    required this.gridOffsetY,
  });

  factory _SecurityLayerLayout.random(math.Random random) {
    double between(double min, double max) =>
        min + random.nextDouble() * (max - min);

    return _SecurityLayerLayout(
      firstX: between(0.12, 0.30),
      firstY: between(0.18, 0.38),
      firstSize: between(280, 360),
      firstRotation: between(-0.10, 0.10),
      secondX: between(0.72, 0.92),
      secondY: between(0.62, 0.84),
      secondSize: between(360, 460),
      secondRotation: between(-0.12, 0.12),
      thirdX: between(0.40, 0.60),
      thirdY: between(0.42, 0.58),
      thirdSize: between(185, 230),
      thirdRotation: between(-0.08, 0.08),
      gridOffsetX: between(0, 80),
      gridOffsetY: between(0, 80),
    );
  }
}

class _SecurityLayersPainter extends CustomPainter {
  final bool isDark;
  final Color primaryColor;
  final _SecurityLayerLayout layout;

  _SecurityLayersPainter({
    required this.isDark,
    required this.primaryColor,
    required this.layout,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final w = size.width;
    final h = size.height;

    // Config colors
    final color1 = isDark
        ? const Color(0xFF0B4D76).withValues(alpha: 0.08)
        : const Color(0xFF18CFE3).withValues(alpha: 0.06);
    final color2 = isDark
        ? const Color(0xFF18CFE3).withValues(alpha: 0.05)
        : const Color(0xFF0B4D76).withValues(alpha: 0.04);
    final gridColor = isDark
        ? Colors.white.withValues(alpha: 0.03)
        : Colors.black.withValues(alpha: 0.03);

    // Draw grid pattern (Tech feel)
    _drawTechGrid(canvas, size, gridColor);

    // Floating Squircle 1 (Top Left)
    _drawSquircle(
      canvas,
      cx: w * layout.firstX,
      cy: h * layout.firstY,
      size: layout.firstSize,
      color: color1,
      rotation: layout.firstRotation,
    );

    // Floating Squircle 2 (Bottom Right)
    _drawSquircle(
      canvas,
      cx: w * layout.secondX,
      cy: h * layout.secondY,
      size: layout.secondSize,
      color: color2,
      rotation: layout.secondRotation,
    );

    // Floating Squircle 3 (Center)
    _drawSquircle(
      canvas,
      cx: w * layout.thirdX,
      cy: h * layout.thirdY,
      size: layout.thirdSize,
      color: primaryColor.withValues(alpha: isDark ? 0.03 : 0.04),
      rotation: layout.thirdRotation,
      stroke: true,
    );
  }

  void _drawTechGrid(Canvas canvas, Size size, Color color) {
    final paint = Paint()
      ..color = color
      ..strokeWidth = 1;

    const step = 80.0;

    // Vertical lines
    for (double x = layout.gridOffsetX; x < size.width; x += step) {
      canvas.drawLine(Offset(x, 0), Offset(x, size.height), paint);
    }

    // Horizontal lines
    for (double y = layout.gridOffsetY; y < size.height; y += step) {
      canvas.drawLine(Offset(0, y), Offset(size.width, y), paint);
    }
  }

  void _drawSquircle(
    Canvas canvas, {
    required double cx,
    required double cy,
    required double size,
    required Color color,
    double rotation = 0,
    bool stroke = false,
  }) {
    canvas.save();
    canvas.translate(cx, cy);
    canvas.rotate(rotation);
    canvas.translate(-size / 2, -size / 2);

    final paint = Paint()..color = color;
    if (stroke) {
      paint.style = PaintingStyle.stroke;
      paint.strokeWidth = 2;
    } else {
      paint.style = PaintingStyle.fill;
    }

    // Use ContinuousRectangleBorder for true squircle shape matching the UI
    final shape = ContinuousRectangleBorder(
      borderRadius: BorderRadius.circular(size * 0.45),
    );

    final rect = Rect.fromLTWH(0, 0, size, size);
    final path = shape.getOuterPath(rect);

    canvas.drawPath(path, paint);

    canvas.restore();
  }

  @override
  bool shouldRepaint(covariant _SecurityLayersPainter oldDelegate) {
    return oldDelegate.isDark != isDark ||
        oldDelegate.primaryColor != primaryColor ||
        oldDelegate.layout != layout;
  }
}
