/* SPDX-License-Identifier: MIT */
DefinitionBlock ("dynamic-host.aml", "DSDT", 2, "STELA", "DYNHOST", 1)
{
    Name (DDBH, Zero)
    Name (UNLD, Zero)
    Name (TBUF, Buffer () {})
    Method (LDTB, 1) { Store (Arg0, TBUF) Load (TBUF, DDBH) Return (One) }
    Method (UDTB, 0) { Unload (DDBH) Store (One, UNLD) Return (One) }
}
