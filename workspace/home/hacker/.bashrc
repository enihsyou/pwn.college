# Note: To make the settings in .bashrc take effect, you need to run `bash`
# again after logging in via SSH to start a new shell.
# This is because the default `bash --login` does not load configuration files
# from the home directory.

# Perform tasks normally done by `bash --login`, as defined in /etc/profile
if [ -d /etc/profile.d ]; then
  for i in /etc/profile.d/*.sh; do
    if [ -r $i ]; then
      . $i
    fi
  done
  unset i
fi

# Define an alias for objdump with Intel syntax and colored jump visualization
alias objdump='objdump -M intel --visualize-jumps=color --disassembler-color=terminal'

# Clipboard helper function:
# The idea is that the current environment's /run/dojo/bin/python may not
# include the tkinter module. However, running `find /nix/store -wholename "*/_tkinter*"`
# shows that the system has multiple valid Python installations that include it.
# So we use one of those Python interpreters to access the GUI clipboard.
function clipboard() {
    local python=/nix/store/6gvxs9gj8baa4rpn1kxbibjwg8xkjn7g-python3-3.13.11-env/bin/python
    if [[ -z "$1" ]]; then
        # Get clipboard content from GUI Desktop
        DISPLAY=:0 "$python" -c "
import tkinter
tk = tkinter.Tk()
tk.withdraw()
print(tk.clipboard_get())
"
    else
        # Set clipboard content to GUI Desktop
        DISPLAY=:0 "$python" -c "
import tkinter, sys
tk = tkinter.Tk()
tk.withdraw()
tk.clipboard_clear()
tk.clipboard_append(sys.argv[1])
" "$1"
    fi
}
