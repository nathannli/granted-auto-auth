#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
source_file=$repository_dir/bin/granted-auto-auth
target_dir=$HOME/.local/bin
target_file=$target_dir/granted-auto-auth

if [ ! -x "$source_file" ]; then
    printf '%s\n' "granted-auto-auth: source is not executable: $source_file" >&2
    exit 1
fi

mkdir -p "$target_dir"

if [ -L "$target_file" ]; then
    if [ "$(readlink "$target_file")" = "$source_file" ]; then
        printf '%s\n' "granted-auto-auth already linked: $target_file"
        exit 0
    fi
    printf '%s\n' "granted-auto-auth: refusing to replace symlink: $target_file" >&2
    exit 1
fi

if [ -e "$target_file" ]; then
    printf '%s\n' "granted-auto-auth: refusing to replace existing path: $target_file" >&2
    exit 1
fi

ln -s "$source_file" "$target_file"
printf '%s\n' "granted-auto-auth linked: $target_file -> $source_file"
