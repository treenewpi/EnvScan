package fk.envscan;

interface IIsolate {
    String snapshot();
    int tracerPid();
    String crcBlob();
    int ppid();
    String selfMaps();
    String selfCtx();
}
