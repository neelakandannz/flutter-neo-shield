import 'package:flutter/material.dart';

/// Reusable card widget for demo items.
class DemoCard extends StatelessWidget {
  /// Creates a [DemoCard] with a title and child content.
  const DemoCard({
    required this.title,
    required this.child,
    super.key,
  });

  /// The card title.
  final String title;

  /// The card content.
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              title,
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.bold,
                  ),
            ),
            const SizedBox(height: 12),
            child,
          ],
        ),
      ),
    );
  }
}
