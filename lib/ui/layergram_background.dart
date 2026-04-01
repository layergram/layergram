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
  final bool reducedEffects;
  final bool pauseAnimation;

  const LayergramBackground({
    super.key,
    required this.child,
    this.reducedEffects = false,
    this.pauseAnimation = false,
  });

  @override
  State<LayergramBackground> createState() => _LayergramBackgroundState();
}

class _LayergramBackgroundState extends State<LayergramBackground>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;

  bool get _shouldAnimate => !widget.reducedEffects && !widget.pauseAnimation;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 30),
    );
    _syncAnimation();
  }

  @override
  void didUpdateWidget(covariant LayergramBackground oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.reducedEffects != widget.reducedEffects ||
        oldWidget.pauseAnimation != widget.pauseAnimation) {
      _syncAnimation();
    }
  }

  void _syncAnimation() {
    if (_shouldAnimate) {
      if (!_controller.isAnimating) {
        _controller.repeat();
      }
      return;
    }
    if (_controller.isAnimating) {
      _controller.stop(canceled: false);
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final dark = theme.brightness == Brightness.dark;
    final painter = _SecurityLayersPainter(
      progress: _controller.value,
      isDark: dark,
      primaryColor: theme.colorScheme.primary,
      reducedEffects: widget.reducedEffects,
    );

    // Tech/Security Palette
    // Dark: Deep slate/blue
    // Light: Crisp white/cyan tint
    final bgColor = dark ? const Color(0xFF050F16) : const Color(0xFFF2F8FA);

    return Stack(
      children: [
        // 1. Solid Base
        Positioned.fill(child: RepaintBoundary(child: ColoredBox(color: bgColor))),

        // 2. Animated Floating Layers
        Positioned.fill(
          child: RepaintBoundary(
            child: _shouldAnimate
                ? AnimatedBuilder(
                    animation: _controller,
                    builder: (context, _) {
                      return CustomPaint(
                        painter: _SecurityLayersPainter(
                          progress: _controller.value,
                          isDark: dark,
                          primaryColor: theme.colorScheme.primary,
                          reducedEffects: widget.reducedEffects,
                        ),
                      );
                    },
                  )
                : CustomPaint(painter: painter),
          ),
        ),

        // 3. Main Content
        Positioned.fill(child: RepaintBoundary(child: widget.child)),
      ],
    );
  }
}

class _SecurityLayersPainter extends CustomPainter {
  final double progress;
  final bool isDark;
  final Color primaryColor;
  final bool reducedEffects;

  _SecurityLayersPainter({
    required this.progress,
    required this.isDark,
    required this.primaryColor,
    required this.reducedEffects,
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
    if (!reducedEffects) {
      _drawTechGrid(canvas, size, gridColor);
    }

    // Floating Squircle 1 (Top Left)
    _drawSquircle(
      canvas,
      cx: w * 0.2 + math.sin(progress * 2 * math.pi) * (reducedEffects ? 0 : 30),
      cy: h * 0.3 + math.cos(progress * 2 * math.pi) * (reducedEffects ? 0 : 20),
      size: reducedEffects ? 260 : 320,
      color: color1,
      rotation: reducedEffects ? 0 : progress * 0.1,
    );

    // Floating Squircle 2 (Bottom Right)
    _drawSquircle(
      canvas,
      cx: w * 0.85 - math.sin(progress * 2 * math.pi) * (reducedEffects ? 0 : 40),
      cy: h * 0.75 - math.cos(progress * 2 * math.pi) * (reducedEffects ? 0 : 30),
      size: reducedEffects ? 320 : 420,
      color: color2,
      rotation: reducedEffects ? 0 : -progress * 0.15,
    );

    // Floating Squircle 3 (Center - Pulse)
    if (!reducedEffects) {
      _drawSquircle(
        canvas,
        cx: w * 0.5,
        cy: h * 0.5,
        size: 200 + math.sin(progress * 4 * math.pi) * 15,
        color: primaryColor.withValues(alpha: isDark ? 0.03 : 0.04),
        rotation: progress * 0.05,
        stroke: true,
      );
    }
  }

  void _drawTechGrid(Canvas canvas, Size size, Color color) {
    final paint = Paint()
      ..color = color
      ..strokeWidth = 1;

    const step = 80.0;

    // Vertical lines
    for (double x = step / 2; x < size.width; x += step) {
      canvas.drawLine(Offset(x, 0), Offset(x, size.height), paint);
    }

    // Horizontal lines
    for (double y = step / 2; y < size.height; y += step) {
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
    return oldDelegate.progress != progress ||
        oldDelegate.isDark != isDark ||
        oldDelegate.primaryColor != primaryColor ||
        oldDelegate.reducedEffects != reducedEffects;
  }
}
