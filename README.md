# Fuzzing_lab

Typical errors and principles of vulnerability detection in software without source codes were studied. Its own fuzzer program was implemented to automatically search for vulnerabilities, with which the executable file was tested.

Functionality:
- modify the original file (single—byte replacement, replacement of several bytes, additional writing to the file);
- replace bytes with boundary values (0x00, 0xFF, 0xFFFF, 0xFFFFFF, 0xFFFFFFFF, 0xFFFF / 2, 0xFFFF / 2 + 1, 0xFFFF / 2 - 1, etc.);
- have an automatic operation mode in which bytes are sequentially replaced in the file;
- find characters separating fields in the file(“, : = ;”);
- expand the values of fields in the file (add to the end, increase the length of lines in the file);
- implement launching the program under study;
- using Dynamic binary instrumentation(DBI) (Intel Pin / DynamoRIO) to measure code coverage during fuzzing;
- implement a feedback fuzzer mode based on code coverage based on saving modified bytes in a file, taking into account their impact on program code coverage;
- detect the occurrence of errors in the application under study;
- receive the error code and the state of the stack and registers at the time of the error;
- log information about errors that occurred and their corresponding input parameters (replacements made) to a file.
