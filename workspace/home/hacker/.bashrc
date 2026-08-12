# Note: To make the settings in .bashrc take effect, you need to run `bash`
# again after logging in via SSH to start a new shell.
# This is because the default `bash --login` does not load configuration files
# from the home directory.

# Perform tasks normally done by `bash --login`, as defined in /etc/profile
# shellcheck source=/dev/null
. /etc/profile

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

# Copies the contents of a file to the local clipboard over SSH using OSC 52.
osc52copy() {
    if [ "$#" -ne 1 ]; then
        echo "Usage: osc52copy <file>" >&2
        return 1
    fi

    printf '\033]52;c;'
    base64 < "$1" | tr -d '\r\n'
    printf '\a'
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

# Found one with fd in /nix/store
export GHIDRA_HOME=/nix/store/k1baic8mns8adsvfgxhdsnwxc4i9kd7l-ghidra-11.4.2/lib/ghidra

# Inspired from https://github.com/h4sh5/ghidra-headless-decompile
ghdecompile() {
    if (( $# != 1 )); then
        echo "Usage: ghidra_decompile <input-file>" >&2
        return 2
    fi

    local input bname
    input="$(realpath -- "$1")" || return
    bname="$(basename -- "$input")" || return

    if [[ ! -r "$input" ]]; then
        echo "ghidra_decompile: cannot read: $input" >&2
        return 1
    fi

    local analyze_headless="$GHIDRA_HOME/support/analyzeHeadless"
    local script_dir="$HOME/.config/ghidra/ghidra_scripts"
    local script_name="Decompile.java"
    local output="$PWD/$bname.c"

    local project_dir="/tmp"
    local project_name="$bname"
    local project_gpr="$project_dir/$project_name.gpr"
    local project_rep="$project_dir/$project_name.rep"

    if [[ ! -x "$analyze_headless" ]]; then
        echo "ghidra_decompile: missing or not executable: $analyze_headless" >&2
        return 1
    fi

    if [[ ! -r "$script_dir/$script_name" ]]; then
        echo "ghidra_decompile: missing $script_dir/$script_name" >&2
        return 1
    fi

    local -a mode_args

    if [[ -f "$project_gpr" && -d "$project_rep" ]]; then
        echo "Project: $project_gpr (reusing)"
        mode_args=(
            -process "$bname"
            -noanalysis
            -readOnly
        )
    elif [[ -e "$project_gpr" || -e "$project_rep" ]]; then
        echo "ghidra_decompile: incomplete project in /tmp:" >&2
        echo "  $project_gpr" >&2
        echo "  $project_rep" >&2
        echo "Remove both files and try again." >&2
        return 1
    else
        echo "Project: $project_gpr (creating)"
        mode_args=(
            -import "$input"
        )
    fi

    echo "Input:   $input"
    echo "Output:  $output"
    echo "Script:  $script_dir/$script_name"

    "$analyze_headless" \
        "$project_dir" "$project_name" \
        "${mode_args[@]}" \
        -scriptPath "$script_dir" \
        -postScript "$script_name" "$output"
}

export PATH="$PATH:./"

# Forcefully enable user site packages, even if PYTHONNOUSERSITE is set by nix makeCWrapper. 
PYTHONPATH="$(python -m site --user-site):$PYTHONPATH"
export PYTHONPATH
