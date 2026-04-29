import os
import response_templates

class FakeFileSystem:
    def __init__(self):
        # In-memory filesystem represented as a nested dictionary
        self.fs = {
            'bin': {},
            'etc': {
                'passwd': response_templates.PASSWD,
                'shadow': response_templates.SHADOW
            },
            'home': {
                'ubuntu': {}
            },
            'root': {
                '.bashrc': '# .bashrc\n',
                'secret.txt': response_templates.SECRET
            },
            'var': {},
            'tmp': {}
        }

    def _resolve_path(self, current_dir, target_path):
        if not target_path:
            return current_dir

        if target_path.startswith('/'):
            parts = target_path.strip('/').split('/')
        else:
            parts = current_dir.strip('/').split('/') + target_path.split('/')

        resolved_parts = []
        for part in parts:
            if part == '' or part == '.':
                continue
            if part == '..':
                if resolved_parts:
                    resolved_parts.pop()
            else:
                resolved_parts.append(part)

        return '/' + '/'.join(resolved_parts)

    def _get_node(self, path):
        if path == '/':
            return self.fs
        
        parts = path.strip('/').split('/')
        current = self.fs
        for part in parts:
            if not part:
                continue
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    def _get_parent_and_name(self, path):
        if path == '/':
            return None, None
        
        parts = path.strip('/').split('/')
        name = parts[-1]
        parent_path = '/' + '/'.join(parts[:-1])
        
        parent_node = self._get_node(parent_path)
        return parent_node, name

    def ls(self, current_dir, target_path=""):
        path = self._resolve_path(current_dir, target_path)
        node = self._get_node(path)
        
        if node is None:
            return f"ls: cannot access '{target_path}': No such file or directory"
        
        if isinstance(node, dict):
            return "  ".join(sorted(node.keys()))
        else:
            return target_path.split('/')[-1]

    def cd(self, current_dir, target_path):
        path = self._resolve_path(current_dir, target_path)
        node = self._get_node(path)
        
        if node is None:
            return current_dir, f"bash: cd: {target_path}: No such file or directory"
        
        if not isinstance(node, dict):
            return current_dir, f"bash: cd: {target_path}: Not a directory"
            
        return path, None

    def cat(self, current_dir, target_path):
        path = self._resolve_path(current_dir, target_path)
        node = self._get_node(path)
        
        if node is None:
            return f"cat: {target_path}: No such file or directory"
        
        if isinstance(node, dict):
            return f"cat: {target_path}: Is a directory"
            
        return str(node)

    def mkdir(self, current_dir, target_path):
        path = self._resolve_path(current_dir, target_path)
        parent, name = self._get_parent_and_name(path)
        
        if parent is None:
            return f"mkdir: cannot create directory '{target_path}': No such file or directory"
            
        if not isinstance(parent, dict):
            return f"mkdir: cannot create directory '{target_path}': Not a directory"
            
        if name in parent:
            return f"mkdir: cannot create directory '{target_path}': File exists"
            
        parent[name] = {}
        return ""

    def touch(self, current_dir, target_path):
        path = self._resolve_path(current_dir, target_path)
        parent, name = self._get_parent_and_name(path)
        
        if parent is None:
            return f"touch: cannot touch '{target_path}': No such file or directory"
            
        if not isinstance(parent, dict):
            return f"touch: cannot touch '{target_path}': Not a directory"
            
        if name not in parent:
            parent[name] = ""
        return ""

    def rm(self, current_dir, target_path, recursive=False):
        path = self._resolve_path(current_dir, target_path)
        if path == '/':
            return "rm: it is dangerous to operate recursively on '/'\nrm: use --no-preserve-root to override this failsafe"
            
        parent, name = self._get_parent_and_name(path)
        
        if parent is None or name not in parent:
            return f"rm: cannot remove '{target_path}': No such file or directory"
            
        node = parent[name]
        if isinstance(node, dict) and not recursive:
            return f"rm: cannot remove '{target_path}': Is a directory"
            
        del parent[name]
        return ""

    def write_file(self, current_dir, target_path, content, append=False):
        path = self._resolve_path(current_dir, target_path)
        parent, name = self._get_parent_and_name(path)
        
        if parent is None:
            return f"bash: {target_path}: No such file or directory"
            
        if not isinstance(parent, dict):
            return f"bash: {target_path}: Not a directory"
            
        if name in parent and isinstance(parent[name], dict):
            return f"bash: {target_path}: Is a directory"
            
        if append and name in parent:
            parent[name] = parent[name] + "\n" + content
        else:
            parent[name] = content
            
        return ""
