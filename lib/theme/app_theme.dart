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

import 'package:flutter/material.dart';

class AppTheme {
  static ThemeData light() {
    // Cyan/teal palette aligned with the app icon
    final scheme = ColorScheme.fromSeed(seedColor: const Color(0xFF18CFE3));
    return ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      textTheme: ThemeData.light().textTheme.copyWith(
            headlineSmall: const TextStyle(
                fontWeight: FontWeight.w700, letterSpacing: -0.3),
            titleLarge: const TextStyle(
                fontWeight: FontWeight.w700, letterSpacing: -0.2),
            titleMedium: const TextStyle(fontWeight: FontWeight.w600),
            bodyLarge: const TextStyle(height: 1.35),
          ),
      scaffoldBackgroundColor: Colors.transparent,
      appBarTheme: AppBarTheme(
        backgroundColor: Colors.white.withValues(alpha: 0.10),
        foregroundColor: scheme.onSurface,
        elevation: 0,
        centerTitle: false,
      ),
      cardTheme: CardThemeData(
        color: Colors.white.withValues(alpha: 0.70),
        elevation: 0,
        shape:
            ContinuousRectangleBorder(borderRadius: BorderRadius.circular(42)),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: Colors.white.withValues(alpha: 0.72),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(24),
          borderSide: BorderSide.none,
        ),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          backgroundColor: scheme.primary,
          foregroundColor: scheme.onPrimary,
          shape: ContinuousRectangleBorder(
              borderRadius: BorderRadius.circular(28)),
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: scheme.primary,
          side: BorderSide(color: scheme.outline),
          shape: ContinuousRectangleBorder(
              borderRadius: BorderRadius.circular(28)),
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
        ),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          foregroundColor: scheme.primary,
          shape: ContinuousRectangleBorder(
              borderRadius: BorderRadius.circular(28)),
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
        ),
      ),
      floatingActionButtonTheme: FloatingActionButtonThemeData(
        backgroundColor: scheme.primary,
        foregroundColor: scheme.onPrimary,
        shape:
            ContinuousRectangleBorder(borderRadius: BorderRadius.circular(40)),
        elevation: 4,
      ),
      tabBarTheme: TabBarThemeData(
        dividerColor: Colors.transparent,
        indicatorColor: Colors.transparent,
        labelStyle: const TextStyle(fontWeight: FontWeight.w700),
      ),
      navigationRailTheme: NavigationRailThemeData(
        backgroundColor: Colors.white.withValues(alpha: 0.08),
        indicatorShape:
            ContinuousRectangleBorder(borderRadius: BorderRadius.circular(28)),
        indicatorColor: scheme.primary.withValues(alpha: 0.25),
      ),
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: Colors.white.withValues(alpha: 0.20),
        indicatorColor: scheme.primary.withValues(alpha: 0.25),
        indicatorShape:
            ContinuousRectangleBorder(borderRadius: BorderRadius.circular(56)),
      ),
      snackBarTheme: SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        backgroundColor: Colors.black.withValues(alpha: 0.75),
        shape:
            ContinuousRectangleBorder(borderRadius: BorderRadius.circular(28)),
      ),
      dialogTheme: DialogThemeData(
        shape:
            ContinuousRectangleBorder(borderRadius: BorderRadius.circular(48)),
        backgroundColor: Colors.white.withValues(alpha: 0.88),
      ),
      bottomSheetTheme: BottomSheetThemeData(
        shape: const ContinuousRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(56)),
        ),
        backgroundColor: Colors.white.withValues(alpha: 0.92),
      ),
      listTileTheme: ListTileThemeData(
        tileColor: Colors.white.withValues(alpha: 0.30),
        shape:
            ContinuousRectangleBorder(borderRadius: BorderRadius.circular(28)),
      ),
      visualDensity: VisualDensity.adaptivePlatformDensity,
    );
  }

  static ThemeData dark() {
    final scheme = ColorScheme.fromSeed(
      seedColor: const Color(0xFF0B4D76),
      brightness: Brightness.dark,
    );
    return ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      textTheme: ThemeData.dark().textTheme.copyWith(
            headlineSmall: const TextStyle(
                fontWeight: FontWeight.w700, letterSpacing: -0.3),
            titleLarge: const TextStyle(
                fontWeight: FontWeight.w700, letterSpacing: -0.2),
            titleMedium: const TextStyle(fontWeight: FontWeight.w600),
            bodyLarge: const TextStyle(height: 1.35),
          ),
      scaffoldBackgroundColor: Colors.transparent,
      appBarTheme: AppBarTheme(
        backgroundColor: Colors.black.withValues(alpha: 0.25),
        foregroundColor: scheme.onSurface,
        elevation: 0,
        centerTitle: false,
      ),
      cardTheme: CardThemeData(
        color: Colors.black.withValues(alpha: 0.30),
        elevation: 0,
        shape:
            ContinuousRectangleBorder(borderRadius: BorderRadius.circular(42)),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: Colors.black.withValues(alpha: 0.24),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(24),
          borderSide: BorderSide.none,
        ),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: FilledButton.styleFrom(
          backgroundColor: scheme.primary,
          foregroundColor: scheme.onPrimary,
          shape: ContinuousRectangleBorder(
              borderRadius: BorderRadius.circular(28)),
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: scheme.primary,
          side: BorderSide(color: scheme.outline),
          shape: ContinuousRectangleBorder(
              borderRadius: BorderRadius.circular(28)),
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
        ),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          foregroundColor: scheme.primary,
          shape: ContinuousRectangleBorder(
              borderRadius: BorderRadius.circular(28)),
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
        ),
      ),
      floatingActionButtonTheme: FloatingActionButtonThemeData(
        backgroundColor: scheme.primary,
        foregroundColor: scheme.onPrimary,
        shape: ContinuousRectangleBorder(borderRadius: BorderRadius.circular(40)),
        elevation: 4,
      ),
      tabBarTheme: TabBarThemeData(
        dividerColor: Colors.transparent,
        indicatorColor: Colors.transparent,
        labelStyle: const TextStyle(fontWeight: FontWeight.w700),
      ),
      navigationRailTheme: NavigationRailThemeData(
        backgroundColor: Colors.black.withValues(alpha: 0.08),
        indicatorShape: ContinuousRectangleBorder(borderRadius: BorderRadius.circular(28)),
        indicatorColor: scheme.primary.withValues(alpha: 0.35),
      ),
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: Colors.black.withValues(alpha: 0.28),
        indicatorColor: scheme.primary.withValues(alpha: 0.35),
        indicatorShape: ContinuousRectangleBorder(borderRadius: BorderRadius.circular(56)),
      ),
      snackBarTheme: SnackBarThemeData(
        behavior: SnackBarBehavior.floating,
        backgroundColor: Colors.black.withValues(alpha: 0.80),
        shape:
            ContinuousRectangleBorder(borderRadius: BorderRadius.circular(28)),
      ),
      dialogTheme: DialogThemeData(
        shape:
            ContinuousRectangleBorder(borderRadius: BorderRadius.circular(48)),
        backgroundColor: const Color(0xFF0F1822).withValues(alpha: 0.92),
      ),
      bottomSheetTheme: BottomSheetThemeData(
        shape: const ContinuousRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(56)),
        ),
        backgroundColor: const Color(0xFF0F1822).withValues(alpha: 0.94),
      ),
      listTileTheme: ListTileThemeData(
        tileColor: Colors.black.withValues(alpha: 0.16),
        shape:
            ContinuousRectangleBorder(borderRadius: BorderRadius.circular(28)),
      ),
      visualDensity: VisualDensity.adaptivePlatformDensity,
    );
  }
}
