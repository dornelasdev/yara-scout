rule PDF_Embedded_Actions : pdf document active_content
{
    meta:
        id = "YS-0002"
        description = "Detects PDF files containing script or launch action indicators"
        author = "dornelasdev"
        created = "2026-09-24"
        license = "MIT"
        category = "document"
        severity = "medium"
        confidence = "medium"
        scope = "file"
        false_positives = "Legitimate interactive PDF forms and documents using JavaScript or launch actions"

    strings:
        $pdf_header = { 25 50 44 46 2D }
        $javascript = "/JavaScript" ascii
        $javascript_short = "/JS" ascii
        $open_action = "/OpenAction" ascii
        $additional_action = "/AA" ascii
        $launch_action = "/Launch" ascii

    condition:
        filesize < 25MB and
        $pdf_header at 0 and
        (
            (($javascript or $javascript_short) and
             ($open_action or $additional_action)) or
            $launch_action
        )
}
