@{
    # Script module or binary module file associated with this manifest.
    RootModule        = 'DscResource.Common.psm1'

    # Version number of this module.
    ModuleVersion     = '0.2.0'

    # ID used to uniquely identify this module
    GUID              = '9c9daa5b-5c00-472d-a588-c96e8e498450'

    # Author of this module
    Author            = 'DSC Community'

    # Company or vendor of this module
    CompanyName       = 'DSC Community'

    # Copyright statement for this module
    Copyright         = 'Copyright the DSC Community contributors. All rights reserved.'

    # Description of the functionality provided by this module
    Description       = 'Common functions used in DSC Resources'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '4.0'

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @('Get-LocalizedData','New-InvalidArgumentException','New-InvalidOperationException','New-InvalidResultException','New-NotImplementedException','New-ObjectNotFoundException','Test-DscParameterState')

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport   = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport   = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData       = @{

        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags         = @('DSC', 'Localization')

            # A URL to the license for this module.
            LicenseUri   = 'https://github.com/dsccommunity/DscResource.Common/blob/master/LICENSE'

            # A URL to the main website for this project.
            ProjectUri   = 'https://github.com/dsccommunity/DscResource.Common'

            # A URL to an icon representing this module.
            IconUri      = 'https://dsccommunity.org/images/DSC_Logo_300p.png'

            # ReleaseNotes of this module
            ReleaseNotes = '# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Updating pipeline files to the latest in the template.
- Updating and added section Code of conduct.
- Updating and added section contribution.
- Update README.md.
- The cmdlet `Get-LocalizedData` can now detect localized filenames
  that are using both the basename and the basename plus the suffix `strings`. E.g.
  - `MSFT_Cluster.psd1`
  - `MSFT_Cluster.strings.psd1`

## [0.1.1] - 2019-11-27

### Added

- New module based on the functions available in DscResource.Template
- Change the minimum requirement to PowerShell 4.0.

### Changed

- skip tests (it ...) using New-CimInstance when OS is not Windows (see issue #1)
- updating secrets and account used
'

            Prerelease   = ''
        } # End of PSData hashtable

    } # End of PrivateData hashtable
}






