/* SPDX-License-Identifier: MIT */
DefinitionBlock ("namespace.aml", "DSDT", 2, "STELA", "AMLTEST", 1)
{
    Scope (\_SB)
    {
        Device (EC00) { Name (_HID, EisaId ("PNP0C09")) }
        Device (UCSI)
        {
            Name (_HID, "PNP0CA0")
            Name (_CID, Package () {"STLA0001", "STLA0002"})
            Name (_DEP, Package () { EC00 })
            Name (_STA, 0x0F)
            Name (INIC, Zero)
            Method (_INI, 0) { Increment (INIC) }
            Name (_CRS, ResourceTemplate () {
                Memory32Fixed (ReadWrite, 0x9000, 0x0210)
            })
            OperationRegion (TEST, SystemMemory, 0x9000, 8)
            Field (TEST, DWordAcc, NoLock, Preserve) { DATA, 32 }
            OperationRegion (ECRG, EmbeddedControl, 0, 0xFF)
            Field (ECRG, ByteAcc, NoLock, Preserve) { ECXX, 8 }
            Method (ECRD, 0) { Return (ECXX) }
            OperationRegion (BADR, SystemMemory, 0xA000, 8)
            Field (BADR, DWordAcc, NoLock, Preserve) { BADW, 32 }
            Method (BARD, 0) { Return (BADW) }
            Name (SYNC, Zero)
            Method (_DSM, 4, Serialized)
            {
                If (LNotEqual (ObjectType (Arg3), 4)) { Return (Buffer () {0}) }
                If (LNotEqual (SizeOf (Arg3), Zero)) { Return (Buffer () {0}) }
                If (LEqual (Arg0, ToUUID ("6f8398c2-7ca4-11e4-ad36-631042b5008f"))) {
                    If (LNotEqual (Arg1, One)) { Return (Buffer () {0}) }
                    If (LEqual (Arg2, Zero)) { Return (Buffer () {7}) }
                    If (LEqual (Arg2, One)) { Store (0x11223344, DATA) Increment (SYNC) Return (SYNC) }
                    If (LEqual (Arg2, 2)) { Return (DATA) }
                }
                Return (Buffer () {0})
            }
            Method (FIRE, 1) { Notify (UCSI, Arg0) }
            Method (PACK, 0) { Return (Package () { 42, "firmware", Buffer () {1,2,3}, Package () {7,8} }) }
            Method (FAIL, 1) { Return (Divide (One, Arg0)) }
        }
        Device (HIDE) { Name (_HID, "PNP0CA0") Name (_STA, Zero) }
    }
}
