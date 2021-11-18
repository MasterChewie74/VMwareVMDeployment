function New-DC01VM {
    <#
    .SYNOPSIS
    This function will create a new virtual machine in Datacenter01 (DC01).
    .DESCRIPTION
    This function will create a new virtual machine in Datacenter01 (DC01) based
    on the information provided to the parameters. This function will connect to
    the vCenter server, build a Guest OS Customization Spec for the VM, then
    create the new VM based off the spec that had been created.
    .PARAMETER NewComputerName
    This defines the computer name for the new virtual machine.
    .PARAMETER IPAddress
    This defines the IP Address for the new virtual machine. The Default Gateway will
    be defined by this IP Address automatically.
    .PARAMETER Network
    This defines the PortGroup that the virtual machine will use for network communication.
    You will need to specify a proper PortGroup used at this location. You can use the 'tab'
    key to cycle through a list of usable PortGroups.
    .PARAMETER Domain
    This defines the Active Directory Domain that the virtual machine will join. You
    must specify a proper Domain. You can use the 'tab' key to cycle through a
    list of possible Domains.
    .PARAMETER Cluster
    This defines the VMware Cluster that the virtual machine will use for CPU
    and memory usage. You can also use a VMware Host or Host Cluster for this
    parameter as well. You will need to specify a proper Resource Pool, Host, or Host
    Cluster for this location. You can use the 'tab' key to cycle through a list of
    usable Resource Pools, Hosts, or Host Clusters
    .PARAMETER DataStore
    This defines the VMware DataStore that the virtual machine will use for its .vmdk
    storage. You can choose a single DataStore, or a Fully Automated SDRS Storage 
    Cluster for this location. You can use the 'tab' key to cycle through a list of
    useable DataStores or SDRS Clusters.
    .PARAMETER VMFolder
    This defines the VMware Folder that the virtual machine will reside in.
    .PARAMETER OperatingSystem
    This defines the operating system that the new virtual machine will install. The
    default is 2016 (Windows Server 2016). You can use the 'tab' key to cycle through
    a list of supported operating systems.
    .PARAMETER NumberofCPUs
    This defines the number of CPUs that are attached to the virtual machine. The 
    default is 2. You must specify a number for this parameter (such as 2, 4, 8).
    .PARAMETER CPUCoresPerSocket
    This defines the number of CPU cores per socket for the VM. You must specify a
    number for this parameter (such as 2, 4, 8).
    .PARAMETER MemoryInGB
    This defines the amount of memory (RAM) attached to the virtual machine. The
    default is 8GB. You must specify a number for this parameter (such as 4, 8, 16,
    32, etc.)
    .NOTES
    Version: 2.2
    Author: MasterChewie74
    .EXAMPLE
    This command will create a new virtual machine with a computer name of 'NewDeployment'
    in the domain.local domain with an IP Address of 192.168.0.74

    New-DC01VM -NewComputerName NewDeployment -IPAddress 192.168.0.74 -Network PG-192.168.0.0 -Domain domain.local -Cluster DC01-CLUSTER1 -DataStore DC01-STORAGE01 -Folder TEST
    #>
    [cmdletbinding(
        DefaultParameterSetName='General'
    )]
    Param(
        [Parameter (HelpMessage='Name for new VM',
                    Mandatory=$true,
                    ParameterSetName='General',
                    Position=0)]
        [Alias('NewVMName','ComputerName')]
        [string[]]$NewComputerName,

        [Parameter (HelpMessage='IP Address for new VM',
                    Mandatory=$true,
                    ParameterSetName='General',
                    Position=1)]
        [string]$IPAddress,

        [Parameter (HelpMessage='Determines which Host Cluster or Resource Pool to use',
                    Mandatory=$true,
                    ParameterSetName='General',
                    Position=2)]
        [ValidateSet('PG-192.168.0.0','PG-192.168.1.0','PG-192.168.2.0')]
        [Alias('PortGroup')]
        [string]$Network,

        [Parameter (HelpMessage='Sets the Domain that the new server will reside in',
                    Mandatory=$true,
                    ParameterSetName='General',
                    Position=3)]
        [ValidateSet('domain.local','domain.com')]
        [string]$Domain,

        [Parameter (HelpMessage='Determines which Host Cluster to use',
                    Mandatory=$true,
                    ParameterSetName='General',
                    Position=4)]
        [ValidateSet('DC01-CLUSTER1','DC01-CLUSTER2')]
        [Alias('Resource','ResourcePool')]
        [string]$Cluster,

        [Parameter (HelpMessage='Determines which Datastore Cluster to use',
                    Mandatory=$true,
                    ParameterSetName='General',
                    Position=5)]
        [ValidateSet('DC01-STORAGE01','DC01-STORAGE02')]
        [Alias('Storage','DataStoreCluster')]
        [string]$DataStore,

        [Parameter (HelpMessage='Determines which VMware folder to use',
                    ParameterSetName='General',
                    Position=6)]
                    [ValidateSet('POC','TEST')]
        [Alias('Folder','Location')]
        [string]$VMFolder = "Testing",

        [Parameter (HelpMessage='Determines which Operating System to use',
                    ParameterSetName='General')]
        [ValidateSet('2016','2019','CentOS7',"CentOS8")]
        [Alias('OS')]
        [string]$OperatingSystem = "2016",

        [Parameter (HelpMessage='Set the server timezone to UTC',
                    ParameterSetName='General')]
        [switch]$UTCTimeZone,

        [Parameter (HelpMessage='Sets the number of CPUs for the new VM',
                    ParameterSetName='General')]
        [int]$NumberOfCPUSockets = 0,

        [Parameter (HelpMessage='Sets the number of CPU cores per socket for the new VM',
                    ParameterSetName='General')]
        [int]$CPUCoresPerSocket = 0,

        [Parameter (HelpMessage='Amount of memory in GB for new VM',
                    ParameterSetName='General')]
        [int]$MemoryInGB = 0,

        [Parameter (HelpMessage='Cancels the Linux Domain Join',
                    ParameterSetName='General')]
        [switch]$NoLinuxDomainJoin
    )

    BEGIN{
        if ($OperatingSystem -like "20*") {
            $EncryptedAdminPass = Read-Host -AsSecureString -Prompt "Please enter the desired Server Administrator Password: "
            $EncryptedAdminPass2 = Read-Host -AsSecureString -Prompt "Please re-enter the desired Server Admin Password:      "
            $AdminPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($EncryptedAdminPass))
            $AdminPass2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($EncryptedAdminPass2))

            Do{
                if ($AdminPass -eq $AdminPass2) {
                    Write-Host "The Passwords Match!"
                    Start-Sleep -Seconds 3
                } else {
                    Write-Host "Passwords do not match!!!"
                    $EncryptedAdminPass = Read-Host -AsSecureString -Prompt "Please enter the desired Administrator Password "
                    $EncryptedAdminPass2 = Read-Host -AsSecureString -Prompt "Please re-enter the desired Admin Password      "
                    $AdminPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($EncryptedAdminPass))
                    $AdminPass2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($EncryptedAdminPass2))
                }
            } Until ($AdminPass -eq $AdminPass2)
        }

        if ($Domain -eq "domain.local") {
            Do {
                $LocalCred1 = Get-Credential -Message "Enter your domain.local Credentials"
                $LocalCred2 = Get-Credential -Message "Verify your domain.local Credentials"
        
                $LC1DM = $LocalCred1.GetNetworkCredential().domain
                $LC1UN = $LocalCred1.GetNetworkCredential().username
                $LC1PW = $LocalCred1.GetNetworkCredential().password
                $LC2DM = $LocalCred2.GetNetworkCredential().domain
                $LC2UN = $LocalCred2.GetNetworkCredential().username
                $LC2PW = $LocalCred2.GetNetworkCredential().password
            } Until (($LC1DM -eq $LC2DM) -and ($LC1UN -eq $LC2UN) -and ($LC1PW -eq $LC2PW))
        
            $Script:DomainCred = $LocalCred1
        } elseif ($Domain -eq "domain.com") {
            Do {
                $ComCred1 = Get-Credential -Message "Enter your domain.com Credentials"
                $ComCred2 = Get-Credential -Message "Verify your domain.com Credentials"
        
                $CC1DM = $ComCred1.GetNetworkCredential().domain
                $CC1UN = $ComCred1.GetNetworkCredential().username
                $CC1PW = $ComCred1.GetNetworkCredential().password
                $CC2DM = $ComCred2.GetNetworkCredential().domain
                $CC2UN = $ComCred2.GetNetworkCredential().username
                $CC2PW = $ComCred2.GetNetworkCredential().password
            } Until (($CC1DM -eq $CC2DM) -and ($CC1UN -eq $CC2UN) -and ($CC1PW -eq $CC2PW))
        
            $Script:DomainCred = $ComCred1
        } 
        
        if (($Domain -eq "domain.com")  -or ($Domain -eq "domain.local")) {
            Do {
                $VCCred1 = Get-Credential -Message "Enter your vCenter Credentials"
                $VCCred2 = Get-Credential -Message "Verify your vCenter Credentials"
        
                $VC1DM = $VCCred1.GetNetworkCredential().domain
                $VC1UN = $VCCred1.GetNetworkCredential().username
                $VC1PW = $VCCred1.GetNetworkCredential().password
                $VC2DM = $VCCred2.GetNetworkCredential().domain
                $VC2UN = $VCCred2.GetNetworkCredential().username
                $VC2PW = $VCCred2.GetNetworkCredential().password
            } Until (($VC1DM -eq $VC2DM) -and ($VC1UN -eq $VC2UN) -and ($VC1PW -eq $VC2PW))
        
            $Script:vCenterCred = $VCCred1
        }

        Clear-Host

        $Script:IPAddress = $IPAddress
        $NewComputerName | Out-File "\\server01.domain.com\folder\$Script:IPAddress-name.txt"
        $Domain | Out-File "\\server01.domain.com\folder\$Script:IPAddress-domain.txt"

        if ($UTCTimeZone -eq $true) {
            $UTC = "Coordinated Universal Time"
            $UTC | Out-File "\\server01.domain.com\Resources\$Script:IPAddress-UTC.txt"
        }

        Set-PowerCLIConfiguration -Scope AllUsers -InvalidCertificateAction Ignore -DefaultVIServerMode Multiple -ParticipateInCeip $false -Confirm:$false | Out-Null
        Connect-VIServer -Server "vcenter.domain.com" -Credential ($Script:vCenterCred)
    }

    PROCESS{
        $PhysicalLocation = "DC01"
        $FQDN = "$NewComputerName.$Domain"
        $DNSEntries = Get-DNSAddress -Location $PhysicalLocation -DNSDomain $Domain -ServerOS $OperatingSystem
        $Gateway = Get-DefaultGateway -NewIP $Script:IPAddress

        #-----Set OU Path-----#
        $OUPath = switch ($Domain) {
            "domain.local" {"OU=Computers,OU=ComputerOU,DC=domain,DC=local"}
            "domain.com" {"OU=Computers,OU=ComputerOU,DC=domain,DC=com"}
        }
        $OUPath | Out-File "\\server01.domain.com\folder\$Script:IPAddress-oupath.txt"

        switch ($OperatingSystem) {
            "2016" {New-WindowsOSCustomization -ServerOS $OperatingSystem -Pass $AdminPass | Out-Null}
            "2019" {New-WindowsOSCustomization -ServerOS $OperatingSystem -Pass $AdminPass | Out-Null}
            "CentOS7" {New-LinuxOSCustomization -DomainName $Domain -DNSAddresses $DNSEntries}
            "CentOS8" {New-LinuxOSCustomization -DomainName $Domain -DNSAddresses $DNSEntries}
        }

        New-OSIPCustomization -ServerOS $OperatingSystem -NewIP $Script:IPAddress -DefaultGW $Gateway -DNSAddresses $DNSEntries | Out-Null
        Remove-SecondaryNICMapping | Out-Null

        $CreateVMParameters = @{
            ServerOS = $OperatingSystem
            HostResource = $Cluster
            Storage = $DataStore
            VMwareFolder = $VMFolder
            Location = $PhysicalLocation
        }

        Create-VMFromTemplate @CreateVMParameters | Out-Null

        if ($OperatingSystem -notlike "20*") {New-InternalDNSRecord -DomainName $Domain -Location $PhysicalLocation}
        
        Get-FloppyDrive -VM $NewComputerName | Remove-FloppyDrive -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Get-NetworkAdapter -VM $NewComputerName | Set-NetworkAdapter -Portgroup (Get-VDPortgroup -Name $Network) -Confirm:$false | Out-Null
        Get-NetworkAdapter -VM $NewComputerName | Set-NetworkAdapter -StartConnected:$true -Confirm:$false | Out-Null

        if ($NumberOfCPUSockets -gt 0) {Set-VM -VM $NewComputerName -NumCpu $NumberOfCPUSockets -Confirm:$false}
        if ($CPUCoresPerSocket -gt 0) {Set-VM -VM $NewComputerName -CoresPerSocket $CPUCoresPerSocket -Confirm:$false}
        if ($MemoryInGB -gt 0) {Set-VM -VM $NewComputerName -MemoryGB $MemoryInGB -Confirm:$false}

        Enable-CPUHotAdd -ComputerName $NewComputerName
        Enable-MemHotAdd -ComputerName $NewComputerName

        Start-VM -VM $NewComputerName

        Do {
            Start-Sleep -Seconds 5
            Write-Host "Still waiting for $FQDN $(Get-Date)"
        } While ((Test-Connection $FQDN -Count 1 -Quiet) -eq $false)
        
        Start-Sleep -Seconds 20
                       
        if (($OperatingSystem -notlike "20*") -and ($NoLinuxDomainJoin -eq $false)) {
            New-LinuxDomainJoin -ServerFQDN $FQDN -Location $PhysicalLocation
        }

        if ($OperatingSystem -like "20*") {Set-PSGallery | Out-Null}

        Write-Host "Creation Complete"
    }

    END{
        $FQDN = "$NewComputerName.$Domain"
        if ($OperatingSystem -like "20*") {
            Invoke-Command -ComputerName $FQDN -Scriptblock {Remove-Item -Path C:\Join.ps1} -Credential ($Script:DomainCred)
            Invoke-Command -ComputerName $FQDN -Scriptblock {Remove-Item -Path C:\Join.key} -Credential ($Script:DomainCred)
            Invoke-Command -ComputerName $FQDN -Scriptblock {Remove-Item -Path C:\Create-Creds.ps1} -Credential ($Script:DomainCred)
            Invoke-Command -ComputerName $FQDN -Scriptblock {Remove-Item -Path C:\AdminPassword.txt} -Credential ($Script:DomainCred)
            Invoke-Command -ComputerName $FQDN -Scriptblock {Remove-Item -Path C:\ComPassword.txt} -Credential ($Script:DomainCred)
            Invoke-Command -ComputerName $FQDN -Scriptblock {Remove-Item -Path C:\LocalPassword.txt} -Credential ($Script:DomainCred)
            Invoke-Command -ComputerName $FQDN -Scriptblock {Remove-Item -Path C:\Reset-WSUSAuth.bat} -Credential ($Script:DomainCred)
        }
        Remove-Item -Path "\\server01.domain.com\folder\$Script:IPAddress-name.txt"
        Remove-Item -Path "\\server01.domain.com\folder\$Script:IPAddress-domain.txt"
        Remove-Item -Path "\\server01.domain.com\folder\$Script:IPAddress-oupath.txt"
        if (Test-Path -Path "\\server01.domain.com\folder\$Script:IPAddress-UTC.txt") {Remove-Item -Path "\\server01.domain.com\folder\$Script:IPAddress-UTC.txt"}
        Get-OSCustomizationSpec -Name $NewComputerName | Remove-OSCustomizationSpec -Confirm:$false
        Disconnect-VIServer -Server "vcenter.domain.com" -Confirm:$false
        Write-Host "Things to complete:"
        Write-Host "Verify CPU & RAM are correct"
        Write-Host "Have a great day!!!"
    }
}

function Get-DNSAddress {
    <#
    .SYNOPSIS
    This function sets the proper DNS Address.
    .DESCRIPTION
    This function will set the DNS Address for the server being created
    based on the Location and the Domain tha the VM will reside in.
    .PARAMETER Location
    This is the physical location of the VM. 
    .PARAMETER DNSDomain
    This is the domain that the VM will reside in.
    .PARAMETER ServerOS
    The Operating System of the VM being built.
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateSet('DC01','DC02')]
        [string[]]$Location,

        [Parameter(Mandatory=$True)]
        [string[]]$DNSDomain,

        [Parameter(Mandatory=$True)]
        [string[]]$ServerOS
    )

    BEGIN{}

    PROCESS{
        $LocationIP= switch ($Location) {
            "DC01" {"168","169"}
            "DC02" {"169","168"}
        }

        $DNSThirdOctet= switch ($DNSDomain) {
            "domain.local" {"0"}
            "domain.com" {"1"}
        }

        $DNSDomainIP= switch ($DNSDomain) {
            "domain.local" {"10","20","21"}
            "domain.com" {"5","20","21"}
        }
        
        if ($ServerOS -notlike "20*") {
            $DNS = "192.$($LocationIP[0]).$DNSThirdOctet.$($DNSDomainIP[1]),192.$($LocationIP[0]).$DNSThirdOctet.$($DNSDomainIP[2]),192.$($LocationIP[1]).$DNSThirdOctet.$($DNSDomainIP[2])"
        } else {
            if ((($Location -eq "DC01") -or ($Location -eq "DC02")) -and ($DNSDomain -eq "domain.local")) {
                $DNS = "192.168.0.40,192.168.1.41"
            } else {
                $DNS = "192.$($LocationIP[0]).$DNSThirdOctet.$($DNSDomainIP[0]),192.$($LocationIP[1]).$DNSThirdOctet.$($DNSDomainIP[0])"
            }
        }

        return $DNS
    }

    END{}
}

function New-InternalDNSRecord {
    <#
    .SYNOPSIS
    Creates Internal DNS Record.
    .DESCRIPTION
    This function creates a new internal DNS record based on the name
    of the new VM being built, the domain that the VM is being built
    in, and the specified IP Address of the new VM. It will choose
    the DNS server based on the location that the New-????VM function
    is running from and the Domain of the specified VM.
    .PARAMETER DomainName
    This is the name of the Domain that the DNS Record will be created in.
    .PARAMETER Location
    This is the Location specified based on the New-????VM function.
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string[]]$DomainName,

        [Parameter(Mandatory=$True)]
        [string[]]$Location
    )

    BEGIN{}

    PROCESS{
        $DNSLocation = switch ($Location) {
            "DC01" {"DC01"}
            "DC02" {"DC01"}
        }

        $DNSServer = switch ($DomainName) {
            "domain.local" {$DNSLocation + "DNS01.domain.local"}
            "domain.com" {$DNSLocation + "DNS01.domain.com"}
        }

        $HostName = Get-Content -Path "\\server.domain.com\folder\$Script:IPAddress-name.txt"
        $SB = {Add-DnsServerResourceRecordA -Name $args[0] -ZoneName $args[1] -IPv4Address $args[2]}

        Invoke-Command -ComputerName $DNSServer -ArgumentList $HostName,$DomainName,$Script:IPAddress -ScriptBlock $SB -Credential $Script:DomainCred
    }

    END{}
}

function Get-DefaultGateway {
    <#
    .SYNOPSIS
    Gets the Default Gateway for an IP Address in DC01
    .DESCRIPTION
    Searches for the Default Gateway for a DC01 IP
    Address and returns the Default Gateway for use.
    .PARAMETER NewIP
    Specifies the IP address used to search for the corresponding
    Default Gateway
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string[]]$NewIP
    )

    BEGIN{}

    PROCESS{
        if ($NewIP -like "192.168.0.*") {$DG = "192.168.0.1"}
        elseif ($NewIP -like "192.168.1.*") {$DG = "192.168.1.1"}

        Write-Output $DG
    }

    END{}
}

function Get-VMwareFolder {
    <#
    .SYNOPSIS
    This function will determine the VMware Folder the VM will reside in. 
    .DESCRIPTION
    ***Some entries in this function have ?'s in place of spaces or underscores***
    ***This is a temporary measure to account for the new 6.7 folder structures***
    This function is used to translate the shortened string, provided in the
    New VM function, to the data that the Create-VMFromTemplate needs to 
    properly place the VM in a VMware Folder. 
    .PARAMETER FolderName
    This is the string name of the folder provided by the New VM function.
    .PARAMETER Location
    This is the physical location of the new VM.
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string[]]$FolderName,

        [Parameter(Mandatory=$True)]
        [string[]]$Location
    )

    BEGIN{}

    PROCESS{
        if ($FolderName -eq "POC") {$FolderPath =  Get-Folder -Name "*POC*" | Get-FolderPath | Where-Object -Property Path -like *$Location*}
        elseif ($FolderName -eq "Test") {$FolderPath =  Get-Folder -Name "*Test*" | Get-FolderPath | Where-Object -Property Path -like *$Location*}

        $ProperFolder = $FolderPath | Get-FolderByPath
        Return $ProperFolder
    }

    END{}
}

function New-WindowsOSCustomization {
    <#
    .SYNOPSIS
    This function builds the Windows Guest Customization Spec for the new VM.
    .DESCRIPTION
    This function will build the VMware Windows Guest Customization Spec based
    on the information provided by the New VM function. 
    .PARAMETER SpecName
    Not being used at this time.
    .PARAMETER Pass
    This is the Administrator Password for the new VM.
    .PARAMETER ServerOS
    This is the Operating System of the new VM.
    #>
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline=$True,
                   ValueFromPipelineByPropertyName=$True)]
        [string]$SpecName,

        [Parameter(ValueFromPipeline=$True,
                   ValueFromPipelineByPropertyName=$True)]
        [string]$Pass,

        [Parameter()]
        [string]$ServerOS
    )

    BEGIN{}

    PROCESS{
        if ($ServerOS -eq "2016") {$ProductKey = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"} #2016 Datacenter Key
        if ($ServerOS -eq "2019") {$ProductKey = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"} #2019 Datacenter Key
        
        $GuestOSParameters = @{
            Name = (Get-Content -Path "\\server01.domain.com\folder\$Script:IPAddress-name.txt")
            Description = "Used to customize the deployment of Windows servers"
            OSType = "Windows"
            Workgroup = "WORKGROUP"
            ProductKey = $ProductKey
            FullName = "Administrator"
            AdminPassword = $Pass
            OrgName = "ORG"
            AutoLogonCount = 1
            GuiRunOnce = "cmd /c PowerShell.exe C:\Join.ps1"
        }

        New-OSCustomizationSpec @GuestOSParameters -ChangeSid
    }

    END{}
}

function New-LinuxOSCustomization {
    <#
    .SYNOPSIS
    This function builds the Linux Guest Customization Spec for the new VM.
    .DESCRIPTION
    This function will build the VMware Linux Guest Customization Spec based
    on the information provided by the New VM function. 
    .PARAMETER DomainName
    Used to specify the Domain Name used for the DNS Suffix
    .PARAMETER DNSAddresses
    This is what specifies the DNS Addresses of the Linux VM.
    #>
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline=$True,
                   ValueFromPipelineByPropertyName=$True)]
        [string]$DomainName,

        [Parameter (ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True)]
        [string]$DNSAddresses
    )

    BEGIN{}

    PROCESS{
        $DNSAddr1 = $DNSAddresses.Split(",")[0]
        $DNSAddr2 = $DNSAddresses.Split(",")[1]

        $GuestOSParameters = @{
            Name = (Get-Content -Path "\\server01.domain.com\folder\$Script:IPAddress-name.txt")
            Description = "Used to customize the deployment of Linux servers"
            OSType = "Linux"
            NamingScheme = "vm"
            DnsServer = $DNSAddr1,$DNSAddr2
            DnsSuffix = $DomainName
            Domain = $DomainName
        }

        New-OSCustomizationSpec @GuestOSParameters
    }

    END{}
}

function New-OSIPCustomization {
    <#
    .SYNOPSIS
    This function specifies the IP Addressing info for the new VM.
    .DESCRIPTION
    This function builds the IP Addressing portion of the VMware Guest
    Customization Spec, and attaches it to the Guest Customization Spec
    that was created for the VM.
    .PARAMETER ServerOS
    OS of Machine being built. Used to determine DNS configuration for
    Windows VS Linux deployments.
    .PARAMETER DefaultGW
    Specifies the Default Gateway of the VM.
    .PARAMETER NewIP
    Specifies the new IP Address of the VM.
    .PARAMETER DNSAddresses
    Specifies the DNS Addresses of the VM. 
    #>
    [cmdletbinding()]
    Param(
        [Parameter (ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True)]
        [string[]]$ServerOS,

        [Parameter (ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True)]
        [string]$DefaultGW,

        [Parameter (ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True)]
        [string]$NewIP,

        [Parameter (ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True)]
        [string]$DNSAddresses
    )

    BEGIN{}

    PROCESS{
        $GuestIPParameters = @{
            OSCustomizationSpec = (Get-Content -Path "\\server01.domain.com\folder\$NewIP-name.txt") 
            IpAddress = $NewIP
            SubnetMask = "255.255.255.0"
            DefaultGateway = $DefaultGW
            IpMode = "UseStaticIP"
            Position = 1
        }

        if ($ServerOS -like "20*") {
            $DNSAddr1 = $DNSAddresses.Split(",")[0]
            $DNSAddr2 = $DNSAddresses.Split(",")[1]

            $GuestIPParameters.Add('DNS',($DNSAddr1,$DNSAddr2))
        }

        New-OSCustomizationNicMapping @GuestIPParameters
    }

    END{}
}

function Remove-SecondaryNICMapping {
    <#
    .SYNOPSIS
    This removes the secondary NIC Mapping from the Guest Customization Spec.
    .DESCRIPTION
    When a new Guest Customization Spec is created, it automatically has a
    DHCP NIC Mapping attached to the customization. When the NIC Configuration
    defined in the New-OSIPCustomization function is attached to the Guest
    Customization Spec, there are then 2 NIC Configurations defined on the 
    Guest Customization Spec. This function removes the secondary DHCP NIC
    Configuration.
    #>

    BEGIN{}

    PROCESS{
        $SpecName = Get-Content -Path "\\server01.domain.com\folder\$Script:IPAddress-name.txt"
        $nicMapping = Get-OSCustomizationSpec -Name $SpecName | Get-OSCustomizationNicMapping | Where-Object {$_.Position -eq 2}
        Remove-OSCustomizationNicMapping -OSCustomizationNicMapping $nicMapping -Confirm:$false
    }

    END{}
}

 function Create-VMFromTemplate {
    <#
    .SYNOPSIS
    Creates a new VM from a template
    .DESCRIPTION
    This will create a VM from a template. It will name the VM in vCenter,
    assign it to a datastore, assign it a host, and a VM Folder location. 
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$ServerOS,

        [Parameter(Mandatory=$True)]
        [string]$HostResource,
        
        [Parameter(Mandatory=$True)]
        [string]$Storage,

        [Parameter(Mandatory=$True)]
        [string]$VMwareFolder,

        [Parameter(Mandatory=$True)]
        [string]$Location
    )

    BEGIN{}

    PROCESS{
        $Template = switch ($ServerOS) {
            "2016" {Get-Template -Name 2016DCTemplate}
            "2019" {Get-Template -Name 2019DCTemplate}
            "CentOS7" {Get-Template -Name CentOS7Template}
            "CentOS8" {Get-Template -Name CentOS8Template}
        }

        $NewVMParameters = @{
            Name = (Get-Content -Path "\\server01.domain.com\folder\$Script:IPAddress-name.txt")
            Template = $Template
            Datastore = $Storage
            ResourcePool = $HostResource
            Location = Get-VMwareFolder -FolderName $VMwareFolder -Location $Location 
            OSCustomizationSpec = (Get-Content -Path "\\server01.domain.com\folder\$Script:IPAddress-name.txt")
        }

        New-VM @NewVMParameters -Confirm:$false
    }

    END{}
}

function Enable-CPUHotAdd {
    <#
    .SYNOPSIS
    Enables the CPU Hot Add Functionality.
    .DESCRIPTION
    Enables the ability for the VM to have CPU resources dynamically added, without
    powering off the VM.
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string[]]$ComputerName
    )

    BEGIN{}

    PROCESS{
        $vmview = Get-vm $ComputerName | Get-View
        $vmConfigSpec = New-Object VMware.Vim.VirtualMachineConfigSpec
        $extra = New-Object VMware.Vim.optionvalue
        $extra.Key="vcpu.hotadd"
        $extra.Value="true"
        $vmConfigSpec.extraconfig += $extra
        $vmview.ReconfigVM($vmConfigSpec)
    }

    END{}
}

function Enable-MemHotAdd {
    <#
    .SYNOPSIS
    Enables the Memory(RAM) Hot Add Functionality.
    .DESCRIPTION
    Enables the ability for the VM to have Memory(RAM) resources dynamically added, without
    powering off the VM.
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string[]]$ComputerName
    )

    BEGIN{}

    PROCESS{
        $vmview = Get-vm $ComputerName | Get-View
        $vmConfigSpec = New-Object VMware.Vim.VirtualMachineConfigSpec
        $extra = New-Object VMware.Vim.optionvalue
        $extra.Key="mem.hotadd"
        $extra.Value="true"
        $vmConfigSpec.extraconfig += $extra
        $vmview.ReconfigVM($vmConfigSpec)
    }

    END{}
}

function Set-PSGallery {
    <#
    .SYNOPSIS
    This function sets the PowerShell Gallery as a trusted repository.
    .DESCRIPTION
    This function will install the NuGet Package Provider, which will allow PowerShell
    Modules to be installed from PowerShell Repositories. It will then set the PowerShell
    Gallery as a trusted repository. This will allow modules from the PowerShell Gallery
    to be installed without requiring extra permissions to complete the installs.
    #>
    [cmdletbinding()]
    Param()

    BEGIN{}

    PROCESS{
        $RegFix1 = {Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord}
        $RegFix2 = {Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord}
        Invoke-Command -ComputerName $FQDN -ScriptBlock $RegFix1 -Credential ($Script:DomainCred)
        Invoke-Command -ComputerName $FQDN -ScriptBlock $RegFix2 -Credential ($Script:DomainCred)

        Invoke-Command -ComputerName $FQDN -ScriptBlock {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12} -Credential ($Script:DomainCred)
        Invoke-Command -ComputerName $FQDN -ScriptBlock {Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force} -Credential ($Script:DomainCred)
        Invoke-Command -ComputerName $FQDN -ScriptBlock {Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted} -Credential ($Script:DomainCred)
    }

    END{}
}

function New-LinuxDomainJoin {
    <#
    .SYNOPSIS
    This function will domain join a Linux VM.
    .DESCRIPTION
    This function will invoke a command on the Ansible server that
    will call an Ansible playbook designed to domain join Linux VMs.
    #>
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$ServerFQDN,

        [Parameter(Mandatory=$True)]
        [string]$Location
    )

    BEGIN{}

    PROCESS{
        $AnsibleCommand = """bash etc/ansible/interfaces/sysprep.sh $ServerFQDN $Script:IPAddress $Location"""
        $FullCommand = "runuser -l ansible -c $AnsibleCommand"

        if ($Location -ne "DC02"){Connect-VIServer -Server "vcenter.domain.com" -Credential $Creds}
        Invoke-VMScript -ScriptText $FullCommand -VM ansible01 -GuestCredential $AnsibleCreds -ScriptType Bash -Server "vcenter.domain.com"
        if ($Location -ne "DC02"){Disconnect-VIServer -Server "vcenter.domain.com" -Confirm:$false}
    }

    END{}
}

function Get-FolderByPath{
    <# 
    .SYNOPSIS
    Retrieve folders by giving a path.
    .DESCRIPTION
    The function will retrieve a folder by it's path. The path can contain any type of leave (folder or datacenter).
    .NOTES
    Author: Luc Dekens
    Edited By: MasterChewie74
        Edits: Changed the Separator value, and added Pipeline input to the Path Parameter.
    .PARAMETER Path 
    The path to the folder. This is a required parameter. 
    .PARAMETER Separator
    The character that is used to separate the leaves in the path. The default is '\' 
    .EXAMPLE
    PS> Get-FolderByPath -Path "Folder1\Datacenter\Folder2"
    .EXAMPLE
    PS> Get-FolderByPath -Path "Folder1>Folder2" -Separator '>'
  #>
   
    param(
        [CmdletBinding()]
        [Parameter (Mandatory = $true,
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True)]
        [System.String[]]${Path},

        [char]${Separator} = '\'
    )
   
    process{
      if((Get-PowerCLIConfiguration).DefaultVIServerMode -eq "Multiple"){
        $vcs = $defaultVIServers
      }
      else{
        $vcs = $defaultVIServers[0]
      }
   
      foreach($vc in $vcs){
        foreach($strPath in $Path){
          $root = Get-Folder -Name Datacenters -Server $vc
          $strPath.Split($Separator) | %{
            $root = Get-Inventory -Name $_ -Location $root -Server $vc -NoRecursion
            if((Get-Inventory -Location $root -NoRecursion | Select -ExpandProperty Name) -contains "vm"){
              $root = Get-Inventory -Name "vm" -Location $root -Server $vc -NoRecursion
            }
          }
          $root | Where-Object {$_ -is [VMware.VimAutomation.ViCore.Impl.V1.Inventory.FolderImpl]} | ForEach-Object {
            Get-Folder -Name $_.Name -Location $root.Parent -NoRecursion -Server $vc
          }
        }
      }
    }
  }

function Get-FolderPath{
    <#
    .SYNOPSIS
        Returns the folderpath for a folder.
    .DESCRIPTION
        The function will return the complete folderpath for
        a given folder, optionally with the "hidden" folders
        included. The function also indicats if it is a "blue"
        or "yellow" folder.
    .NOTES
        Authors:	Luc Dekens
    .PARAMETER Folder
        One or more folders
    .PARAMETER ShowHidden
        Switch to specify if "hidden" folders should be included
        in the returned path. The default is $false.
    .EXAMPLE
        PS> Get-FolderPath -Folder (Get-Folder -Name "MyFolder")
    .EXAMPLE
        PS> Get-Folder | Get-FolderPath -ShowHidden:$true
    #>
    
    param(
    [parameter(valuefrompipeline = $true,
    position = 0,
    HelpMessage = "Enter a folder")]
    [VMware.VimAutomation.ViCore.Impl.V1.Inventory.FolderImpl[]]$Folder,
    [switch]$ShowHidden = $false
    )
    
    begin{
        $excludedNames = "Datacenters","vm","host"
    }
    
    process{
        $Folder | %{
            $fld = $_.Extensiondata
            $fldType = "yellow"
            if($fld.ChildType -contains "VirtualMachine"){
                $fldType = "blue"
            }
            $path = $fld.Name
            while($fld.Parent){
                $fld = Get-View $fld.Parent
                if((!$ShowHidden -and $excludedNames -notcontains $fld.Name) -or $ShowHidden){
                    $path = $fld.Name + "\" + $path
                }
            }
            $row = "" | Select Name,Path,Type
            $row.Name = $_.Name
            $row.Path = $path
            $row.Type = $fldType
            $row
        }
    }
}

Export-ModuleMember -Function New-DC01VM