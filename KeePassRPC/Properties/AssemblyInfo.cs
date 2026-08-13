using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

// General assembly properties
[assembly: AssemblyTitle("KeePassRPC")]
[assembly: AssemblyDescription("A Remote Procedure Call (RPC) server for KeePass. Used by the Kee browser extension.")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("Kee Vault Ltd")]
[assembly: AssemblyProduct("KeePass Plugin")]
[assembly: AssemblyCopyright("Copyright © 2024 Chris Tomlinson")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]

// COM settings
[assembly: ComVisible(false)]

// Assembly GUID
[assembly: Guid("89631AAE-8DE6-4593-8DAB-AB28490A490A")]

// Assembly version information
[assembly: AssemblyVersion("3.0.0.0")]
[assembly: AssemblyFileVersion("3.0.0.0")] // also change AssemblyVersion and PluginVersion in KeePassRPCExt.cs!

// The SRP exchange and the hashing it is built on are internal, and the tests that check
// the 2048-bit group has to run a full exchange to be worth anything. Widening the
// plugin's public surface for a test would be the worse trade.
[assembly: InternalsVisibleTo("KeePassRPCTest")]
