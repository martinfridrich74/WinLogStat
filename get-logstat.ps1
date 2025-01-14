param(
    # Pocatni pocet dnu pro analyzu (vychozi 1)
    [int]$Days = 1,

    # Nazy logu k analyze. Muzu je zadat vice, oddelene carkami
    [string[]]$LogNames = @('Security','System')
)

# Tento kod se spusti pri volani skriptu s parametrem -?
if ($args -contains "-?") {
    Get-Help $MyInvocation.MyCommand
    return
}

Write-Host "Analyzuji logy: $($LogNames -join ', ')"
Write-Host "Pocet dnu zpetne: $Days"

# Vypocitame datum/cas, od ktereho se budou udalosti nacet
$startTime = (Get-Date).AddDays(-$Days)
Write-Host "Analyzuji udalosti od: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))"

# Funkce pro zaokrouhleni casu na 15minutovy blok
function Get-QuarterHourBlock {
    param([datetime]$EventTime)

    # Overime, ze cas udalosti neni null a je v rozumnem rozsahu
    if ($EventTime -eq $null) {
        return $null
    }
    if ($EventTime.Year -lt 1 -or $EventTime.Year -gt 9999) {
        return $null
    }

    # 1) Vynulujeme sekundy
    $roundedTime = $EventTime.AddSeconds(-$EventTime.Second)
    # 2) Zaokrouhlime minuty na 0, 15, 30 nebo 45
    $minuteOffset = $roundedTime.Minute % 15
    $roundedTime = $roundedTime.AddMinutes(-$minuteOffset)

    return $roundedTime
}

# Vytvorime a spustime job pro kazdy log
$jobs = @()
foreach ($logName in $LogNames) {
    $jobs += Start-Job -ScriptBlock {
        param($LogName, $startTime)

        # Funkce pro analyzu logu
        function Get-QuarterHourBlock {
            param([datetime]$EventTime)
            if ($EventTime -eq $null) { return $null }
            if ($EventTime.Year -lt 1 -or $EventTime.Year -gt 9999) { return $null }
            $roundedTime = $EventTime.AddSeconds(-$EventTime.Second)
            $minuteOffset = $roundedTime.Minute % 15
            return $roundedTime.AddMinutes(-$minuteOffset)
        }

        Write-Host "`nZpracovavam log: $LogName ..."

        # Stopky pro zmereni casu zpracovani konkretniho logu
        $logStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        $groups = @{}        # Hashtable: klic = casovy blok, hodnota = pocet udalosti
        $totalCount = 0      # Celkovy pocet validnich udalosti
        $totalSize = 0       # Celkova velikost udalosti v bytech

        # Nacetame udalosti z logu a rovnou zpracovavame
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = $LogName
            StartTime = $startTime
        } -ErrorAction SilentlyContinue

        $totalEvents = $events.Count
        $counter = 0

        $events | ForEach-Object {
            $counter++
            
            # Overime TimeCreated
            if ($_.TimeCreated -ne $null -and
                $_.TimeCreated.Year -ge 1 -and $_.TimeCreated.Year -le 9999) {

                $totalCount++

                # Ziskame textovou zpravu udalosti
                $eventMessage = $_.Message

                # Ziskame ID udalosti a dalsi parametry, pokud jsou
                $eventId = $_.Id
                $eventProvider = $_.ProviderName
                $eventLevel = $_.LevelDisplayName

                # Spocitame velikost udalosti jako soucet delky ID, zpravy a dalsich parametru
                $eventSize = ($eventMessage.Length + $eventId.ToString().Length + $eventProvider.Length + $eventLevel.Length)

                # Pricteme velikost udalosti
                $totalSize += $eventSize

                # Urcime 15minutovy blok
                $block = Get-QuarterHourBlock $_.TimeCreated
                if ($block -ne $null) {
                    if (-not $groups.ContainsKey($block)) {
                        $groups[$block] = 1
                    }
                    else {
                        $groups[$block]++
                    }
                }
            }

            # Aktualizace progress baru
            $percentComplete = ($counter / $totalEvents) * 100
            Write-Progress -PercentComplete $percentComplete -Status "Zpracovavam log $LogName" -Activity "Analyza udalosti"
        }

        # Hotovo s nacitanim a tridim do intervalu
        $logStopwatch.Stop()

        if ($totalCount -eq 0) {
            Write-Host "Log '$LogName' je prazdny nebo neobsahuje zadne validni udalosti."
            # Zobrazime cas zpracovani
            $timeSpan = $logStopwatch.Elapsed
            $elapsedTime = '{0}:{1:00}' -f [int]$timeSpan.TotalMinutes, $timeSpan.Seconds
            Write-Host "Cas zpracovani: $elapsedTime (min:sec)"
            return
        }

        Write-Host "Celkovy pocet validnich udalosti: $totalCount"

        # Vypocet prumerne velikosti udalosti v bytech
        $averageSize = $totalSize / $totalCount
        Write-Host "Prumerna velikost udalosti: $([math]::Round($averageSize, 2)) bytes"

        # Najdeme 15min. blok s nejvetsim pocet událostí
        $maxBlock = $null
        $maxCount = 0

        foreach ($blockKey in $groups.Keys) {
            $count = $groups[$blockKey]
            if ($count -gt $maxCount) {
                $maxCount = $count
                $maxBlock = $blockKey
            }
        }

        if ($maxBlock) {
            $intervalStart = $maxBlock
            $intervalEnd = $intervalStart.AddMinutes(15)
            Write-Host "`n-- Nejvetsi 15min. interval --"
            Write-Host "Od:    $intervalStart"
            Write-Host "Do:    $intervalEnd"
            Write-Host "Pocet udalosti: $maxCount"
        }

        # Zobrazime cas zpracovani ve formatu min:sec
        $timeSpan = $logStopwatch.Elapsed
        $elapsedTime = '{0}:{1:00}' -f [int]$timeSpan.TotalMinutes, $timeSpan.Seconds
        Write-Host "`nCas zpracovani logu '$LogName': $elapsedTime (min:sec)"
    } -ArgumentList $logName, $startTime
}

# Cekame na dokonceni vsech jobu
$jobs | ForEach-Object {
    # Wait for job completion
    $result = Receive-Job -Job $_ -Wait
    Remove-Job -Job $_
}

Write-Host "`nAnalyza dokoncena."
