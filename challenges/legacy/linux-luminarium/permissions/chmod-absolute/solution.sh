chmod $(/challenge/run | grep Needed | grep -oE '[rwx-]{9}' | sed -E '
  s/(...)(...)(...)/u=\1,g=\2,o=\3/;
  s/([uga])=---/\1=@/g;
  s/-//g;
  s/@/-/g
') /challenge/pwn
