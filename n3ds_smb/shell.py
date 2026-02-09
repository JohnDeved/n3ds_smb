"""Interactive shell for the 3DS microSD file browser."""

import cmd, ntpath, os


def _safe_name(name):
    """Replace control chars with visible escapes for display."""
    return name.translate({c: f"\\x{c:02x}" for c in range(0x20) if c not in (0x09,)})


class Shell(cmd.Cmd):
    intro = "Type 'help' for commands."
    prompt = "3ds> "

    def __init__(self, client):
        super().__init__()
        self.c, self.cwd = client, "\\"

    def _r(self, arg):
        return ntpath.normpath(ntpath.join(self.cwd, arg)) if arg else self.cwd

    def do_ls(self, arg):
        """ls [path] -- list directory contents"""
        try:
            for e in self.c.listdir(self._r(arg)):
                if e["name"] in (".", ".."):
                    continue
                k = "<DIR>" if e["is_dir"] else f"{e['size']:>10,}"
                print(f"  {k:>12}  {_safe_name(e['name'])}")
        except Exception as e:
            print(f"  error: {e}")

    def do_cd(self, arg):
        """cd [path] -- change directory (no arg = root)"""
        if not arg:
            self.cwd = "\\"
            return
        try:
            self.c.listdir(self._r(arg))
            self.cwd = self._r(arg)
        except Exception as e:
            print(f"  error: {e}")

    def do_pwd(self, _):
        """pwd -- print working directory"""
        print(f"  {self.cwd}")

    def do_get(self, arg):
        """get <remote> [local] -- download file"""
        parts = arg.split(None, 1)
        if not parts:
            print("  usage: get <remote> [local]")
            return
        try:
            remote = self._r(parts[0])
            local = parts[1] if len(parts) > 1 else ntpath.basename(remote)
            with open(local, "wb") as f:
                n = self.c.get_file(remote, f)
            print(f"  {n:,} bytes -> {local}")
        except Exception as e:
            print(f"  error: {e}")

    def do_put(self, arg):
        """put <local> [remote] -- upload file"""
        parts = arg.split(None, 1)
        if not parts:
            print("  usage: put <local> [remote]")
            return
        try:
            local = parts[0]
            remote = self._r(parts[1] if len(parts) > 1 else os.path.basename(local))
            with open(local, "rb") as f:
                n = self.c.put_file(remote, f)
            print(f"  {n:,} bytes -> {remote}")
        except Exception as e:
            print(f"  error: {e}")

    def do_mkdir(self, arg):
        """mkdir <path> -- create directory"""
        if not arg:
            print("  usage: mkdir <path>")
            return
        try:
            self.c.mkdir(self._r(arg))
        except Exception as e:
            print(f"  error: {e}")

    def do_rm(self, arg):
        """rm <file> -- delete file"""
        if not arg:
            print("  usage: rm <file>")
            return
        try:
            self.c.delete(self._r(arg))
        except Exception as e:
            print(f"  error: {e}")

    def do_rmdir(self, arg):
        """rmdir <path> -- remove empty directory"""
        if not arg:
            print("  usage: rmdir <path>")
            return
        try:
            self.c.rmdir(self._r(arg))
        except Exception as e:
            print(f"  error: {e}")

    def do_mv(self, arg):
        """mv <old> <new> -- rename/move file (copies + deletes)"""
        parts = arg.split(None, 1)
        if len(parts) != 2:
            print("  usage: mv <old> <new>")
            return
        try:
            self.c.rename(self._r(parts[0]), self._r(parts[1]))
        except Exception as e:
            print(f"  error: {e}")

    def do_tree(self, arg):
        """tree [path] -- recursive directory listing"""
        try:
            self._tree(self._r(arg) if arg else self.cwd, "")
        except Exception as e:
            print(f"  error: {e}")

    def _tree(self, path, indent):
        for e in self.c.listdir(path):
            if e["name"] in (".", ".."):
                continue
            name = _safe_name(e["name"])
            if e["is_dir"]:
                print(f"{indent}{name}/")
                self._tree(ntpath.join(path, e["name"]), indent + "  ")
            else:
                print(f"{indent}{name}  ({e['size']:,})")

    def do_quit(self, _):
        """quit -- exit the shell"""
        return True

    do_exit = do_q = do_EOF = do_quit
