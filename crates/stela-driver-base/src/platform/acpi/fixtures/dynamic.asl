/* SPDX-License-Identifier: MIT */
DefinitionBlock ("dynamic.aml", "SSDT", 2, "STELA", "DYNAMIC", 1)
{
    External (\DDBH, UnknownObj)
    External (\UDTB, MethodObj)
    Scope (\_SB) {
        Device (DYN0) {
            Name (_HID, "STLA0003")
            Name (TEST, 0x1234)
            Method (REFR, 0) { Return (Package () { DYN0 }) }
            Method (SELF, 0) { Unload (\DDBH) Return (One) }
            Method (NEST, 0) { Return (\UDTB ()) }
            Method (FIRE, 1) { Notify (DYN0, Arg0) }
        }
    }
}
