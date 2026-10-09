def io_kit_user_headers():
    """The two IOKitLib public headers installed under <IOKit/...>.

    They live at this directory's root upstream; consumers include them as
    <IOKit/IOKitLib.h> and <IOKit/IOCFPlugIn.h>, so the generated SDK stages
    copies into an IOKit/ namespace.
    """
    native.export_file(
        name = "IOKitLibHeader",
        src = "IOKitLib.h",
        visibility = ["PUBLIC"],
    )
    native.export_file(
        name = "IOCFPlugInHeader",
        src = "IOCFPlugIn.h",
        visibility = ["PUBLIC"],
    )
