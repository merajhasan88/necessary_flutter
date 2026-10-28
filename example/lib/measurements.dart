// Reading a scan: every measurement the signed report carried, each with its
// status and its fields as the phone sent them, grouped by what it catches --
// the hooks, gadgets and changes in memory first. A measurement the backend
// did not ask for shows as not asked rather than disappearing. The titles and
// descriptions follow the integration guide's sections 6 and 8.
import 'package:flutter/material.dart';
import 'package:necessary/necessary.dart';

/// What a group of measurements catches.
enum MeasurementGroup {
  hooks(
    'Hooks, gadgets and memory changes',
    'Frida and other instrumentation, found by name, by port, by thread and '
        'by memory layout; debuggers and tracers; and the code in memory '
        'compared with its file, where an inline hook changes bytes. A '
        'backend asks for every one of these on every scan.',
  ),
  app(
    'The app as built',
    'What is installed: its identity, its hashes and its signer.',
  ),
  system(
    'Root, jailbreak and the system',
    'Traces of root or a jailbreak, and how the system is set up.',
  ),
  device('Device and network', 'Sent with every scan, asked for or not.'),
  personal(
    'Personal measurements',
    'Asked for by the backend, and measured only where this app turned them '
        'on.',
  );

  const MeasurementGroup(this.title, this.note);

  final String title;
  final String note;
}

/// A measurement's name in the report, a title, what it tells a backend,
/// and its group.
class MeasurementInfo {
  const MeasurementInfo(this.name, this.title, this.about, this.group);

  final String name;
  final String title;
  final String about;
  final MeasurementGroup group;
}

const List<MeasurementInfo> androidMeasurements = <MeasurementInfo>[
  MeasurementInfo(
    'runtime_maps',
    'Memory map',
    "Instrumentation and hooking frameworks named in the app's memory map: "
        'Frida, its gadget, Objection, Xposed and others.',
    MeasurementGroup.hooks,
  ),
  MeasurementInfo(
    'frida_ports',
    'Frida ports',
    "Frida's default local ports accepting connections.",
    MeasurementGroup.hooks,
  ),
  MeasurementInfo(
    'instrumentation_threads',
    'Instrumentation threads',
    'Threads an instrumentation runtime creates, even renamed.',
    MeasurementGroup.hooks,
  ),
  MeasurementInfo(
    'exec_mappings',
    'Executable memory',
    'Memory both writable and executable, executable memory from deleted '
        'files, unlabelled executable regions: where injected code lives.',
    MeasurementGroup.hooks,
  ),
  MeasurementInfo(
    'code_integrity',
    'Code integrity',
    "The app's native code and the system libraries in memory compared with "
        'their files: an inline hook changes bytes, and diff_bytes counts '
        'them.',
    MeasurementGroup.hooks,
  ),
  MeasurementInfo(
    'tracer',
    'Tracer',
    'Another process tracing the app.',
    MeasurementGroup.hooks,
  ),
  MeasurementInfo(
    'debug_state',
    'Debugger',
    'A Java debugger attached or awaited.',
    MeasurementGroup.hooks,
  ),
  MeasurementInfo(
    'app_identity',
    'App identity',
    'The installed app: package, the base APK hash, signing certificates, '
        'flags, install source and split APKs.',
    MeasurementGroup.app,
  ),
  MeasurementInfo(
    'root_files',
    'Root files',
    'Known root, su and framework paths that exist; a test-keys build.',
    MeasurementGroup.system,
  ),
  MeasurementInfo(
    'root_shell',
    'Root shell',
    "Whether su resolves from the app's shell.",
    MeasurementGroup.system,
  ),
  MeasurementInfo(
    'system_properties',
    'System properties',
    'Build and boot-security properties.',
    MeasurementGroup.system,
  ),
  MeasurementInfo(
    'selinux',
    'SELinux',
    'The SELinux mode, read two ways.',
    MeasurementGroup.system,
  ),
  MeasurementInfo(
    'mounts',
    'Mounts',
    'System partitions mounted writable.',
    MeasurementGroup.system,
  ),
  MeasurementInfo(
    'developer_settings',
    'Developer settings',
    'Developer options and USB debugging.',
    MeasurementGroup.system,
  ),
  MeasurementInfo(
    'emulator',
    'Emulator',
    'Build values typical of an emulator.',
    MeasurementGroup.system,
  ),
  MeasurementInfo(
    'device',
    'Device',
    "The OS version, security patch level, model, build, the app's ABI and "
        'memory page size.',
    MeasurementGroup.device,
  ),
  MeasurementInfo(
    'network',
    'Network',
    'A VPN up on any network; an HTTP proxy set.',
    MeasurementGroup.device,
  ),
];

const List<MeasurementInfo> iosMeasurements = <MeasurementInfo>[
  MeasurementInfo(
    'dyld_images',
    'Loaded libraries',
    'Instrumentation and jailbreak names among the loaded libraries: Frida, '
        'its gadget, Cycript, Substrate and others.',
    MeasurementGroup.hooks,
  ),
  MeasurementInfo(
    'environment',
    'Environment',
    'Libraries injected through the environment.',
    MeasurementGroup.hooks,
  ),
  MeasurementInfo(
    'code_integrity',
    'Code integrity',
    "The app's code in memory compared with its file, image by image: an "
        'inline hook changes bytes, and app_diff_bytes counts them.',
    MeasurementGroup.hooks,
  ),
  MeasurementInfo(
    'debugger',
    'Debugger',
    'A debugger tracing the process.',
    MeasurementGroup.hooks,
  ),
  MeasurementInfo(
    'app_identity',
    'App identity',
    "The installed app and its executable's hash.",
    MeasurementGroup.app,
  ),
  MeasurementInfo(
    'code_signing',
    'Code signing',
    "The executable's own code signature.",
    MeasurementGroup.app,
  ),
  MeasurementInfo(
    'jailbreak_files',
    'Jailbreak files',
    'Known jailbreak paths that exist.',
    MeasurementGroup.system,
  ),
  MeasurementInfo(
    'sandbox',
    'Sandbox',
    'Whether the app can write outside its sandbox.',
    MeasurementGroup.system,
  ),
  MeasurementInfo(
    'simulator',
    'Simulator',
    'The simulator, and the hardware model.',
    MeasurementGroup.system,
  ),
  MeasurementInfo(
    'device',
    'Device',
    'The OS version and build, and the model.',
    MeasurementGroup.device,
  ),
  MeasurementInfo(
    'network',
    'Network',
    'A VPN, inferred from the interfaces the proxy settings are scoped to; '
        'an HTTP proxy.',
    MeasurementGroup.device,
  ),
];

/// The personal measurements, in the order of [PersonalMeasurement].
const List<MeasurementInfo> personalCatalog = <MeasurementInfo>[
  MeasurementInfo(
    'local_addresses',
    'Local addresses',
    "The phone's own IP addresses, link-local ones left out.",
    MeasurementGroup.personal,
  ),
  MeasurementInfo(
    'accessibility',
    'Accessibility',
    'The Accessibility services that are on, and the keyboard in use. '
        'Android only.',
    MeasurementGroup.personal,
  ),
  MeasurementInfo(
    'notification_access',
    'Notification access',
    'The apps allowed to read notifications. Android only.',
    MeasurementGroup.personal,
  ),
  MeasurementInfo(
    'other_access',
    'Other access',
    'Device-administrator apps, and known remote-control apps installed. '
        'Android only.',
    MeasurementGroup.personal,
  ),
  MeasurementInfo(
    'screen_capture',
    'Screen capture',
    'The screen being recorded, mirrored or cast.',
    MeasurementGroup.personal,
  ),
  MeasurementInfo(
    'location',
    'Location',
    'The last location the phone already knows: never a fresh fix, never a '
        'prompt. Needs the location permission.',
    MeasurementGroup.personal,
  ),
  MeasurementInfo(
    'mock_location',
    'Mock location',
    'Whether that location was faked.',
    MeasurementGroup.personal,
  ),
];

/// What a personal measurement reports, for its switch.
MeasurementInfo personalInfo(PersonalMeasurement measurement) => personalCatalog
    .firstWhere((MeasurementInfo info) => info.name == measurement.wireName);

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
    final List<MeasurementInfo> catalog = <MeasurementInfo>[
      ...(platform == 'ios' ? iosMeasurements : androidMeasurements),
      ...personalCatalog,
    ];
    Widget tile(MeasurementInfo info) => MeasurementTile(
      info: info,
      result: results[info.name] is Map
          ? Map<String, dynamic>.from(results[info.name] as Map)
          : null,
      asked: required.contains(info.name) || optional.contains(info.name),
    );
    final List<Widget> groups = <Widget>[];
    for (final MeasurementGroup group in MeasurementGroup.values) {
      final List<MeasurementInfo> members = <MeasurementInfo>[
        for (final MeasurementInfo info in catalog)
          if (info.group == group &&
              (group != MeasurementGroup.personal ||
                  optional.contains(info.name) ||
                  results.containsKey(info.name)))
            info,
      ];
      groups.add(
        _Group(
          title: group.title,
          note: group == MeasurementGroup.personal
              ? '${group.note} On: '
                    '${enabled.isEmpty ? 'none' : enabled.join(', ')}.'
              : group.note,
          tiles: <Widget>[
            for (final MeasurementInfo info in members) tile(info),
            if (members.isEmpty) const Text('The backend asked for none.'),
          ],
        ),
      );
    }
    final List<String> other = <String>[
      for (final String name in results.keys)
        if (!catalog.any((MeasurementInfo info) => info.name == name)) name,
    ];
    if (other.isNotEmpty) {
      groups.add(
        _Group(
          title: 'Other measurements',
          note: 'In the report as sent.',
          tiles: <Widget>[
            for (final String name in other)
              tile(
                MeasurementInfo(
                  name,
                  name,
                  'Not described here.',
                  MeasurementGroup.device,
                ),
              ),
          ],
        ),
      );
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        Text(
          'The phone reports what it measured; your backend decides what it '
          'means.',
          style: Theme.of(context).textTheme.bodySmall
              ?.copyWith(fontStyle: FontStyle.italic),
        ),
        ...groups,
      ],
    );
  }
}

/// A measurement's status as the badge says it: whether the phone measured
/// it, never whether what it found is good or bad.
const Map<String, String> _statusLabels = <String, String>{
  'ok': 'measured',
  'error': 'failed',
  'not_enabled': 'off',
};

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
  const MeasurementTile({
    super.key,
    required this.info,
    required this.result,
    this.asked = true,
  });

  final MeasurementInfo info;

  /// The measurement as the report carries it, or null when it is absent.
  final Map<String, dynamic>? result;

  /// Whether the backend asked for it in this scan.
  final bool asked;

  @override
  Widget build(BuildContext context) {
    final Map<String, dynamic>? value = result;
    final Object? unread = value?['unread'];
    final bool partly = unread is Map && unread.isNotEmpty;
    final String status = value == null
        ? (asked ? 'missing' : 'not asked')
        : (value['status'] as String? ?? 'no status');
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
            _statusLabels[status] ?? status,
            warning:
                status == 'error' ||
                status == 'missing' ||
                (status == 'not asked' && info.group == MeasurementGroup.hooks),
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
          Text(
            asked
                ? 'Asked for, but not in the report: a backend refuses such '
                      'a report.'
                : 'Not asked for in this scan, so not measured.',
          )
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
        : label == 'measured'
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
