import time
import random
import re
import shlex
from fake_filesystem import FakeFileSystem
import response_templates

class CommandHandler:
    def __init__(self, session_id):
        self.session_id = session_id
        self.fs = FakeFileSystem()
        self.cwd = '/root'
        self.username = 'root'
        self.history = []
        self.tags = set()

    def get_prompt(self):
        # Format: root@ubuntu:/current/path#
        prompt_char = '#' if self.username == 'root' else '$'
        hostname = 'ubuntu'
        
        # Display ~ for home directory
        display_path = self.cwd
        home_dir = f'/home/{self.username}'
        if self.username == 'root' and self.cwd == '/root':
            display_path = '~'
        elif self.cwd == home_dir:
            display_path = '~'
        elif self.cwd.startswith(home_dir + '/'):
            display_path = '~' + self.cwd[len(home_dir):]
            
        return f"{self.username}@{hostname}:{display_path}{prompt_char} "

    def handle_command(self, command_line):
        if not command_line.strip():
            return ""

        self.history.append(command_line)
        
        # Simulate realistic delay (0.2 - 1.0 sec)
        time.sleep(random.uniform(0.2, 1.0))

        # Handle basic redirection (e.g. echo "text" > file.txt)
        redirect_match = re.search(r'>\s*([^\s]+)$', command_line)
        redirect_file = None
        append = False
        
        if redirect_match:
            redirect_file = redirect_match.group(1)
            # Check if it's >>
            if '>>' in command_line:
                append = True
                command_line = command_line.rsplit('>>', 1)[0].strip()
            else:
                command_line = command_line.rsplit('>', 1)[0].strip()

        try:
            # Parse command, preserving quoted strings
            parts = shlex.split(command_line)
        except ValueError:
            # Fallback if shlex fails (e.g. unmatched quotes)
            parts = command_line.split()
            
        if not parts:
            return ""

        cmd = parts[0].lower()
        args = parts[1:]

        # Execute command
        output = ""
        
        if cmd == 'whoami':
            output = self.username
            
        elif cmd == 'pwd':
            output = self.cwd
            
        elif cmd == 'ls':
            target = args[0] if args else ""
            output = self.fs.ls(self.cwd, target)
            
        elif cmd == 'cd':
            target = args[0] if args else f"/home/{self.username}"
            if self.username == 'root' and not args:
                target = '/root'
            new_cwd, err = self.fs.cd(self.cwd, target)
            if err:
                output = err
            else:
                self.cwd = new_cwd
                
        elif cmd == 'cat':
            if not args:
                output = "cat: missing operand"
            else:
                outputs = []
                for arg in args:
                    if "passwd" in arg or "shadow" in arg:
                        self.tags.add("data_exfiltration")
                    outputs.append(self.fs.cat(self.cwd, arg))
                output = "\n".join(outputs)
                
        elif cmd == 'mkdir':
            if not args:
                output = "mkdir: missing operand"
            else:
                outputs = []
                for arg in args:
                    err = self.fs.mkdir(self.cwd, arg)
                    if err:
                        outputs.append(err)
                output = "\n".join(outputs) if outputs else ""
                
        elif cmd == 'touch':
            if not args:
                output = "touch: missing file operand"
            else:
                outputs = []
                for arg in args:
                    err = self.fs.touch(self.cwd, arg)
                    if err:
                        outputs.append(err)
                output = "\n".join(outputs) if outputs else ""
                
        elif cmd == 'rm':
            if not args:
                output = "rm: missing operand"
            else:
                recursive = '-r' in args or '-rf' in args or '-R' in args
                targets = [a for a in args if not a.startswith('-')]
                outputs = []
                for target in targets:
                    err = self.fs.rm(self.cwd, target, recursive)
                    if err:
                        outputs.append(err)
                output = "\n".join(outputs) if outputs else ""
                
        elif cmd == 'echo':
            output = " ".join(args)
            
        elif cmd == 'uname':
            if '-a' in args or '--all' in args:
                output = response_templates.UNAME
            else:
                output = "Linux"
                
        elif cmd == 'id':
            if self.username == 'root':
                output = response_templates.ID_ROOT
            else:
                output = response_templates.ID_USER
                
        elif cmd == 'ps':
            output = response_templates.PS
            
        elif cmd in ['ifconfig', 'ip']:
            output = response_templates.IFCONFIG
            
        # Simulated malicious commands
        elif cmd in ['wget', 'curl']:
            self.tags.add("malware")
            url = args[0] if args else "http://example.com/file"
            if cmd == 'wget':
                output = f"--2024-04-29 12:00:00--  {url}\nResolving host... 104.21.45.1\nConnecting to 104.21.45.1:80... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 1048576 (1.0M) [application/x-sh]\nSaving to: 'downloaded_file'\n\n     0K .......... .......... .......... .......... ..........  4%  100K 10s\n  1000K .......... .......... .......... .......... ........  100% 1.5M=0.8s\n\n2024-04-29 12:00:01 (1.2 MB/s) - 'downloaded_file' saved [1048576/1048576]"
                self.fs.touch(self.cwd, "downloaded_file")
            else:
                output = f"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n                                 Dload  Upload   Total   Spent    Left  Speed\n100 1024k  100 1024k    0     0  1200k      0 --:--:-- --:--:-- --:--:-- 1205k"
                if '-o' in args or '-O' in args:
                    try:
                        idx = args.index('-o') if '-o' in args else args.index('-O')
                        filename = args[idx+1]
                        self.fs.touch(self.cwd, filename)
                    except (ValueError, IndexError):
                        pass

        elif cmd == 'chmod':
            self.tags.add("privilege_escalation")
            if not args or len(args) < 2:
                output = "chmod: missing operand"
            else:
                # Silently succeed
                output = ""
                
        elif cmd == 'sudo':
            self.tags.add("privilege_escalation")
            output = "[sudo] password for ubuntu: \nSorry, try again.\n[sudo] password for ubuntu: \nsudo: 3 incorrect password attempts"
            
        elif cmd == 'bash' or cmd == 'sh':
            if args:
                # Simulate running a script
                output = ""
            else:
                # Don't actually spawn a new shell, just return empty to simulate success
                output = ""

        elif cmd in ['exit', 'quit', 'logout']:
            return "LOGOUT"

        else:
            output = f"bash: {cmd}: command not found"

        # Handle output redirection
        if redirect_file:
            err = self.fs.write_file(self.cwd, redirect_file, output, append)
            if err:
                return err
            return ""

        return output
