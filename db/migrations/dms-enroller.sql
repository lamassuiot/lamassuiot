CREATE DATABASE dmsenroller;

\connect dmsenroller

CREATE TABLE public.dms_store (
    id TEXT PRIMARY KEY,
    name TEXT,
    serialNumber TEXT,
    keyType TEXT,
    keyBits int,
    csrBase64 TEXT,
    status TEXT,
    creation_ts timestamp,
    modification_ts timestamp
);

CREATE TABLE public.authorized_cas (
    dmsid TEXT,
    caname  TEXT,
    PRIMARY KEY (dmsid,caname)
);