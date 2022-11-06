# BwE File Comparator

![Github Logo](https://rimgo.vern.cc/d2bFmXy.png)

Tool for analysing and comparing files (in bulk) but is mainly intended for binary files (firmware flashes, executables, malware etc).

Performs the following functions:

## Comparative Analysis
1. Compare Offsets (Hex) (Result - Filename)
2. Compare Offsets (ASCII) (Result - Filename)
3. Compare Offsets MD5 (MD5 Hash - Filename)
4. Dual Offsets Comparison (Result 1 - Result 2 - Filename)
5. Dynamic Offset MD5 Calculation (Size - MD5 - Filename)

## Statistical Analysis
6. Compare Offsets Entropy (log2(256)) (Entropy - Filename)
7. Compare File Entropy (log2(256)) (Entropy - Filename)
8. Compare File Statistics (00 Count % / FF Count % - Filename)

## Hash/Other Analysis
9. Obtain File MD5s (MD5 Hash - Filename)
10. Obtain File SHA1s (SHA1 Hash - Filename)
11. Obtain MIME Types (MIME - Filename)

