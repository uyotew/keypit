_comp_keypit() {
  local cur="$2"
  local prev="$3"
  local cmds="get show modify new copy rename remove change-password"

  for word in ${COMP_WORDS[@]:1}; do
    for cmd in $cmds ; do
      if [ "$word" == "$cmd" ]; then
        return
      fi
    done
  done

  case "$prev" in
  "-d") COMPREPLY=($(compgen -f -- "$cur")); return;;
  "-p") return;;
  esac

  if [ "${cur:0:1}" = "-" ]; then
    COMPREPLY+=($(compgen -W "-d -p -h -v --stdout --help --version" -- "$cur"))
  fi
  COMPREPLY+=($(compgen -W "$cmds" -- "$cur"))
}

complete -o nosort -F _comp_keypit keypit
