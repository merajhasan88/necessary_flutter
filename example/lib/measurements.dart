// Reading a scan: what the backend asked for, and every measurement the
// signed report carried -- each with its status and its fields, as the phone
// sent them. The titles and descriptions follow the integration guide's
// sections 6 and 8.
import 'package:flutter/material.dart';
import 'package:necessary/necessary.dart';

/// A measurement's name in the report, a title, and what it tells a backend.
class MeasurementInfo {
  const MeasurementInfo(this.name, this.title, this.about);

  final String name;
  final String title;
  final String about;
}

const List<MeasurementInfo> androidMeasurements = <MeasurementInfo>[
  MeasurementInfo(
    'app_identity',
    'App identity',
    'The installed app: package, the base APK hash, signing certificates, '
        'flags, install source and split APKs.',
  ),
  MeasurementInfo(
    'debug_state',
    'Debugger',
    'A Java debugger attached or awaited.',
  ),
  MeasurementInfo('tracer', 'Tracer', 'Another process tracing the app.'),
  MeasurementInfo(
    'root_files',
    'Root files',
    'Known root, su and framework paths that exist; a test-keys build.',
  ),
  MeasurementInfo(
    'root_shell',
    'Root shell',
    "Whether su resolves from the app's shell.",
  ),
  MeasurementInfo(
    'system_properties',
    'System properties',
    'Build and boot-security properties.',
  ),
  MeasurementInfo('selinux', 'SELinux', 'The SELinux mode, read two ways.'),
  MeasurementInfo('mounts', 'Mounts', 'System partitions mounted writable.'),
  MeasurementInfo(
    'runtime_maps',
    'Memory map',
    "Instrumentation and hooking frameworks named in the app's memory map.",
  ),
  MeasurementInfo(
    'frida_ports',
    'Frida ports',
    "Frida's default local ports accepting connections.",
  ),
  MeasurementInfo(
    'instrumentation_threads',
    'Instrumentation threads',
    'Threads an instrumentation runtime creates, even renamed.',
  ),
  MeasurementInfo(
    'exec_mappings',
    'Executable memory',
    'Memory both writable and executable, executable memory from deleted '
        'files, unlabelled executable regions.',
  ),
  MeasurementInfo(
    'code_integrity',
    'Code integrity',
    "The app's native code and the system libraries in memory compared with "
        'their files: an inline hook changes bytes.',
  ),
  MeasurementInfo(
    'developer_settings',
    'Developer settings',
    'Developer options and USB debugging.',
  ),
  MeasurementInfo(
    'emulator',
    'Emulator',
    'Build values typical of an emulator.',
  ),
  MeasurementInfo(
    'device',
    'Device',
    "The OS version, security patch level, model, build, the app's ABI and "
        'memory page size.',
  ),
  MeasurementInfo(
    'network',
    'Network',
    'A VPN up on any network; an HTTP proxy set.',
  ),
];

const List<MeasurementInfo> iosMeasurements = <MeasurementInfo>[
  MeasurementInfo(
    'app_identity',
    'App identity',
    "The installed app and its executable's hash.",
  ),
  MeasurementInfo(
    'code_signing',
    'Code signing',
    "The executable's own code signature.",
  ),
  MeasurementInfo('debugger', 'Debugger', 'A debugger tracing the process.'),
  MeasurementInfo(
    'jailbreak_files',
    'Jailbreak files',
    'Known jailbreak paths that exist.',
  ),
  MeasurementInfo(
    'sandbox',
    'Sandbox',
    'Whether the app can write outside its sandbox.',
  ),
  MeasurementInfo(
    'dyld_images',
    'Loaded libraries',
    'Instrumentation and jailbreak names among the loaded libraries.',
  ),
  MeasurementInfo(
    'environment',
    'Environment',
    'Libraries injected through the environment.',
  ),
  MeasurementInfo(
    'simulator',
    'Simulator',
    'The simulator, and the hardware model.',
  ),
  MeasurementInfo(
    'code_integrity',
    'Code integrity',
    "The app's code in memory compared with its file, image by image.",
  ),
  MeasurementInfo(
    'device',
    'Device',
    'The OS version and build, and the model.',
  ),
  MeasurementInfo(
    'network',
    'Network',
    'A VPN, inferred from the interfaces the proxy settings are scoped to; '
        'an HTTP proxy.',
  ),
];

/// The personal measurements, in the order of [PersonalMeasurement].
const List<MeasurementInfo> personalCatalog = <MeasurementInfo>[
  MeasurementInfo(
    'local_addresses',
    'Local addresses',
    "The phone's own IP addresses, link-local ones left out.",
  ),
  MeasurementInfo(
    'accessibility',
    'Accessibility',
    'The Accessibility services that are on, and the keyboard in use. '
        'Android only.',
  ),
  MeasurementInfo(
    'notification_access',
    'Notification access',
    'The apps allowed to read notifications. Android only.',
  ),
  MeasurementInfo(
    'other_access',
    'Other access',
    'Device-administrator apps, and known remote-control apps installed. '
        'Android only.',
  ),
  MeasurementInfo(
    'screen_capture',
    'Screen capture',
    'The screen being recorded, mirrored or cast.',
  ),
  MeasurementInfo(
    'location',
    'Location',
    'The last location the phone already knows: never a fresh fix, never a '
        'prompt. Needs the location permission.',
  ),
  MeasurementInfo(
    'mock_location',
    'Mock location',
    'Whether that location was faked.',
  ),
];

/// What a personal measurement reports, for its switch.
MeasurementInfo personalInfo(PersonalMeasurement measurement) => personalCatalog
    .firstWhere((MeasurementInfo info) => info.name == measurement.wireName);

/// Measurements every report carries, asked for or not.
const Map<String, Set<String>> sentWithEveryScan = <String, Set<String>>{
  'android': <String>{'device', 'network'},
  'ios': <String>{'device', 'network', 'code_integrity'},
};

/// One scan as the phone sent it: the backend's plan -- [required] and the
/// personal measurements it asked for, [optional] -- and the report's
/// [results] (`probe_results`).
class ScanView extends StatelessWidget {
  const ScanView({
    super.key,
    required this.platform,
    required this.required,
    required this.optional,
    required this.results,
    required this.enabled,
  });

  final String platform;
  final List<String> required;
  final List<String> optional;
  final Map<String, dynamic> results;

  /// The personal measurements the app enabled for this scan.
  final List<String> enabled;

  @override
  Widget build(BuildContext context) {
    final List<MeasurementInfo> catalog = platform == 'ios'
        ? iosMeasurements
        : androidMeasurements;
    MeasurementInfo info(String name) =>
        <MeasurementInfo>[...catalog, ...personalCatalog].firstWhere(
          (MeasurementInfo known) => known.name == name,
          orElse: () => MeasurementInfo(name, name, 'Not described here.'),
        );
    final Set<String> always = sentWithEveryScan[platform] ?? <String>{};
    final List<String> asked = <String>[
      for (final MeasurementInfo known in catalog)
        if (required.contains(known.name)) known.name,
      for (final String name in required)
        if (!catalog.any((MeasurementInfo known) => known.name == name)) name,
    ];
    final List<String> volunteered = <String>[
      for (final MeasurementInfo known in catalog)
        if (always.contains(known.name) &&
            !required.contains(known.name) &&
            results.containsKey(known.name))
          known.name,
    ];
    final List<String> personal = <String>[
      for (final MeasurementInfo known in personalCatalog)
        if (optional.contains(known.name) || results.containsKey(known.name))
          known.name,
    ];
    final Set<String> shown = <String>{...asked, ...volunteered, ...personal};
    final List<String> other = <String>[
      for (final String name in results.keys)
        if (!shown.contains(name)) name,
    ];
    final List<String> notAsked = <String>[
      for (final MeasurementInfo known in catalog)
        if (!shown.contains(known.name) && !results.containsKey(known.name))
          known.title,
    ];
    Widget group(String title, String note, List<String> names) => _Group(
      title: title,
      note: note,
      tiles: <Widget>[
        for (final String name in names)
          MeasurementTile(
            info: info(name),
            result: results[name] is Map
                ? Map<String, dynamic>.from(results[name] as Map)
                : null,
          ),
      ],
    );
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        if (asked.isNotEmpty)
          group(
            'Asked for by the backend',
            'Its plan for this scan: the measurements it relies on every '
                'time, and others varied from scan to scan.',
            asked,
          ),
        if (volunteered.isNotEmpty)
          group('Sent with every scan', 'Asked for or not.', volunteered),
        if (personal.isNotEmpty)
          group(
            'Personal measurements',
            'Asked for by the backend; measured only where this app turned '
                'them on (${enabled.isEmpty ? 'none is on' : enabled.join(', ')}).',
            personal,
          ),
        if (other.isNotEmpty)
          group('Other measurements', 'In the report as sent.', other),
        if (notAsked.isNotEmpty)
          Padding(
            padding: const EdgeInsets.only(top: 8),
            child: Text(
              'Not asked for in this scan: ${notAsked.join(', ')}.',
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ),
      ],
    );
  }
}

class _Group extends StatelessWidget {
  const _Group({required this.title, required this.note, required this.tiles});

  final String title;
  final String note;
  final List<Widget> tiles;

  @override
  Widget build(BuildContext context) {
    final TextTheme text = Theme.of(context).textTheme;
    return Padding(
      padding: const EdgeInsets.only(top: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: <Widget>[
          Text(title, style: text.titleSmall),
          Text(note, style: text.bodySmall),
          ...tiles,
        ],
      ),
    );
  }
}

/// One measurement: its title and status, opening to what it tells a
/// backend and every field the phone sent.
class MeasurementTile extends StatelessWidget {
  const MeasurementTile({super.key, required this.info, required this.result});

  final MeasurementInfo info;

  /// The measurement as the report carries it, or null when it is absent.
  final Map<String, dynamic>? result;

  @override
  Widget build(BuildContext context) {
    final Map<String, dynamic>? value = result;
    final Object? unread = value?['unread'];
    final bool partly = unread is Map && unread.isNotEmpty;
    return ExpansionTile(
      key: ValueKey<String>('measurement:${info.name}'),
      dense: true,
      tilePadding: EdgeInsets.zero,
      shape: const Border(),
      collapsedShape: const Border(),
      title: Row(
        children: <Widget>[
          Expanded(child: Text(info.title)),
          if (partly) const _Badge('unread', warning: true),
          if (value?['truncated'] == true) const _Badge('truncated'),
          _Badge(
            value == null
                ? 'missing'
                : (value['status'] as String? ?? 'no status'),
            warning: value == null || value['status'] == 'error',
          ),
        ],
      ),
      subtitle: Text(
        info.name,
        style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
      ),
      expandedCrossAxisAlignment: CrossAxisAlignment.stretch,
      childrenPadding: const EdgeInsets.only(bottom: 12),
      children: <Widget>[
        Text(info.about, style: Theme.of(context).textTheme.bodySmall),
        if (value == null)
          const Text('Not in the report.')
        else ...<Widget>[
          if (value['status'] == 'not_enabled')
            const Text('The backend asked; this app has not turned it on.'),
          if (partly)
            Text(
              'Parts it could not read are not measured: never read them as '
              'a clean "no".',
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ...fieldRows(context, <String, dynamic>{
            for (final MapEntry<String, dynamic> entry in value.entries)
              if (entry.key != 'status') entry.key: entry.value,
          }),
        ],
      ],
    );
  }
}

/// Every field of [fields], nested maps and lists indented under their
/// name.
List<Widget> fieldRows(
  BuildContext context,
  Map<String, dynamic> fields, {
  int depth = 0,
}) {
  final List<Widget> rows = <Widget>[];
  fields.forEach((String name, dynamic value) {
    if (value is Map && value.isNotEmpty) {
      rows.add(_FieldRow(name: name, depth: depth));
      rows.addAll(
        fieldRows(context, Map<String, dynamic>.from(value), depth: depth + 1),
      );
    } else if (value is List && value.any((dynamic item) => item is Map)) {
      rows.add(_FieldRow(name: name, value: '${value.length}', depth: depth));
      for (int i = 0; i < value.length; i++) {
        final dynamic item = value[i];
        rows.addAll(
          item is Map
              ? fieldRows(context, <String, dynamic>{
                  for (final MapEntry<dynamic, dynamic> entry in item.entries)
                    '${i + 1}. ${entry.key}': entry.value,
                }, depth: depth + 1)
              : <Widget>[
                  _FieldRow(
                    name: '${i + 1}.',
                    value: _scalar(item),
                    depth: depth + 1,
                  ),
                ],
        );
      }
    } else {
      rows.add(_FieldRow(name: name, value: _scalar(value), depth: depth));
    }
  });
  return rows;
}

String _scalar(dynamic value) {
  if (value == null) {
    return 'null';
  }
  if (value is bool) {
    return value ? 'yes' : 'no';
  }
  if (value is List) {
    return value.isEmpty ? 'none' : value.map(_scalar).join(', ');
  }
  if (value is Map) {
    return 'none';
  }
  final String text = '$value';
  return text.isEmpty ? '""' : text;
}

class _FieldRow extends StatelessWidget {
  const _FieldRow({required this.name, this.value, required this.depth});

  final String name;
  final String? value;
  final int depth;

  @override
  Widget build(BuildContext context) {
    final TextTheme text = Theme.of(context).textTheme;
    return Padding(
      padding: EdgeInsets.only(left: 12.0 * depth, top: 2, bottom: 2),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Expanded(
            flex: 5,
            child: Text(
              name,
              style: text.bodySmall?.copyWith(fontWeight: FontWeight.w600),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            flex: 6,
            child: SelectableText(value ?? '', style: text.bodySmall),
          ),
        ],
      ),
    );
  }
}

class _Badge extends StatelessWidget {
  const _Badge(this.label, {this.warning = false});

  final String label;
  final bool warning;

  @override
  Widget build(BuildContext context) {
    final ColorScheme colors = Theme.of(context).colorScheme;
    final Color color = warning
        ? colors.error
        : label == 'ok'
        ? colors.primary
        : colors.outline;
    return Container(
      margin: const EdgeInsets.only(left: 6),
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
      decoration: BoxDecoration(
        border: Border.all(color: color),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Text(
        label,
        style: Theme.of(context).textTheme.labelSmall?.copyWith(color: color),
      ),
    );
  }
}
