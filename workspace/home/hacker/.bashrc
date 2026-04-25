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
alias objdump='objdump -M intel --visualize-jumps=color --disassembler-color=on --unicode=highlight'

alias ls='eza'

# Get clipboard content from Desktop
# The idea is that the current environment's /run/dojo/bin/python may not
# include the tkinter module. However, running `find /nix/store -wholename "*/_tkinter*"`
# shows that the system has multiple valid Python installations that include it.
# So we use one of those Python interpreters to access the GUI clipboard.
# But set clipboard have a little problem, as data we set through clipboard_append()
# is not sync to system clipboard consistently.
function clipboard() {
    local python=/nix/store/6gvxs9gj8baa4rpn1kxbibjwg8xkjn7g-python3-3.13.11-env/bin/python
    DISPLAY=:0 "$python" -c "
import tkinter, sys
tk = tkinter.Tk()
tk.withdraw()
try:
    print(tk.clipboard_get())
except tkinter.TclError:
    try:
        print(tk.selection_get(selection='PRIMARY'))
    except tkinter.TclError:
        print('Clipboard is empty or not accessible', file=sys.stderr)
"
}

# Send request with nc but using curl syntax.
# designed for 'Playing With Programs / Taking Web' section.
function curlnc() {
    target_host="challenge.localhost"
    target_port="80"
    socket_path="/tmp/curlnc.sock"
    pid_file="/tmp/curlnc.pid"
    (
        socat UNIX-LISTEN:"$socket_path",fork EXEC:"nc $target_host $target_port" &
        echo $! >"$pid_file"
    )
    curl -v --unix-socket "$socket_path" "http://$target_host${1:-/}" "${@:2}"
    kill "$(cat "$pid_file")"
    rm -f "$pid_file" "$socket_path"
}

# Spin up process with a stable, clean environment,
# which is useful for finding stack address on ASLR-disabled program.
function withenv() {
    # create runtime.env with `env -0 > runtime.env`
    (cat runtime.env; printf "%s\0" "$@") | xargs -0 env -i
}

export PATH="$PATH:./"
