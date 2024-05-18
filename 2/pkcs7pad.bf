Note: assumes null terminated input with 0 for end of input
, # Read block size (which must not be 0) into $0
[->+>+<<] # Set $1=block size; $2=remaining block size (=$1 initially); $0=0; $3=$4=0
>>>>,[.>+<,]> # Pass null terminated input through and count the length into $5; dp=5
[ # While length /= 0; dp=5
  -<<<- # Decrement $2=remaining block size and $5=length; dp=2
  >+<[>-]>[-<< # If $2=0 then; dp=1
    [-<+>>+<] <[->+<]>> # Copy $1 to $2 using $0
  >>] # end if; dp=4
>]<<<< # Now $2=remaining block size=padchar; dp=1
[-]> [-<+<+>>] < # Set $0=$1=padchar; dp=1
[<.>-] # Print padchar times padchar
