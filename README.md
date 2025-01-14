# WinLogStat
Count EPS statistics from Windows Log 

    
    Tento skript analyzuje logy systemu Windows a provadi ruzne statistiky na zaklade zadaneho casoveho obdobi.
    Parametry logu, jako jsou nazy logu a casove obdobi, lze upravit dle potreby.
    
    Tento skript analyzuje Windows logy na zaklade casoveho intervalu, vypocita prumerou velikost udalosti v bytech
    a identifikuje nejvetsi 15minutovy casovy blok s nejvice udalostmi.

    .DESCRIPTION
    Skript umoznuje uzivateli zadat nazev logu (napriklad "Security", "System") a pocet dnu, pro ktere maji byt
    udalosti analyzovany. Na zaklade techto parametru skript provede analyzu udalosti, vcetne vypoctu prumerne velikosti
    udalosti a identifikace nejvetsiho casoveho intervalu s nejvice udalostmi.

    .PARAMETER Days
    Pocet dnu, ktere chcete zpetne analyzovat. Vychozi hodnota je 1.

    .PARAMETER LogNames
    Nazy logu k analyze (napr. "Security", "System"). Muzete zadat vice logu oddelene carkou.

    .EXAMPLE
    .\get-logstat.ps1 -Days 30 -LogNames 'Security', 'System'
    Tento priklad provede analyzu logu "Security" a "System" za poslednich 30 dnu.

    .EXAMPLE
    .\get-logstat.ps1 -Days 7 -LogNames 'Application'
    Tento priklad provede analyzu logu "Application" za poslednich 7 dnu.

    .EXAMPLE
    .\get-logstat.ps1 -Days 60 -LogNames 'Security'
    Tento priklad provede analyzu logu "Security" za poslednich 60 dnu.
