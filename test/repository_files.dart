// The files the tests share with the backends: the measurement contract and
// the client-server vectors. They sit beside the package, or above it when
// the package is part of a larger repository.
import 'dart:io';

/// [path] in the nearest folder, from the package up, that holds it.
File repositoryFile(String path) =>
    File(_nearest(path, (String found) => File(found).existsSync()));

/// The folder [path] in the nearest folder, from the package up, that holds it.
Directory repositoryDirectory(String path) =>
    Directory(_nearest(path, (String found) => Directory(found).existsSync()));

String _nearest(String path, bool Function(String) exists) {
  Directory folder = Directory.current.absolute;
  while (!exists('${folder.path}/$path')) {
    if (folder.parent.path == folder.path) {
      throw StateError('$path: in no folder from ${Directory.current.path} up');
    }
    folder = folder.parent;
  }
  return '${folder.path}/$path';
}
