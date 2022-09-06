$pdf_mode = 1;
$latex = 'latex -halt-on-error %O --shell-escape %S ';
$pdflatex = 'lualatex --halt-on-error -file-line-error %O %S';
$pdf_previewer = 'open';
$clean_ext = 'pdfsync bbl loa synctex.gz';
