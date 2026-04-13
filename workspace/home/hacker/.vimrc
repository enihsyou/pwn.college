" activates syntax highlighting among other things
syntax on

set nocompatible        " use vim defaults
set scrolloff=3         " keep 3 lines when scrolling
set ai                  " set auto-indenting on for programming
set noswapfile          " disable swap file since we constantly ssh in and out

set showcmd             " display incomplete commands
set nobackup            " do not keep a backup file
set number              " show line numbers
set relativenumber      " show relative line numbers
set ruler               " show the current row and column

augroup numbertoggle
  autocmd!
  autocmd BufEnter,FocusGained,InsertLeave,WinEnter * if &nu && mode() != "i" | set rnu   | endif
  autocmd BufLeave,FocusLost,InsertEnter,WinLeave   * if &nu                  | set nornu | endif
augroup END

set hlsearch            " highlight searches
set incsearch           " do incremental searching
set showmatch           " jump to matches when entering regexp
set ignorecase          " ignore case when searching
set smartcase           " no ignorecase if Uppercase char present

set expandtab
set tabstop=4
set shiftwidth=4

nnoremap <F5> :w<CR>:!python3 %<CR>
nnoremap <leader>r :w<CR>:bo term ++noclose ++rows=15 python3 %<CR>
