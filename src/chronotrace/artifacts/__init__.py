"""Artifact plugins package."""

from chronotrace.extract.file_metadata import FileMetadataPlugin
from chronotrace.artifacts.ntfs_mft import NtfsMftPlugin
from chronotrace.artifacts.evtx import EvtxPlugin
from chronotrace.artifacts.prefetch import PrefetchPlugin
from chronotrace.artifacts.registry import RegistryPlugin
from chronotrace.artifacts.browser import BrowserPlugin
from chronotrace.artifacts.lnk import LnkPlugin
from chronotrace.artifacts.logs import LogsPlugin
from chronotrace.artifacts.network import NetworkLogPlugin

__all__ = [
    "FileMetadataPlugin",
    "NtfsMftPlugin",
    "EvtxPlugin",
    "PrefetchPlugin",
    "RegistryPlugin",
    "BrowserPlugin",
    "LnkPlugin",
    "LogsPlugin",
    "NetworkLogPlugin",
]
