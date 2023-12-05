namespace Antivirus_api;

public class InformationAboutScanning
{
    public int CountFiles { get; set; } = 0;
    public int CountJSfiles { get; set; } = 0;
    public int CountRmDetecs { get; set; } = 0;
    public int CountRundll32Detecs { get; set; } = 0;
    public int CountOtherErrors { get; set; } = 0;
    
    public static InformationAboutScanning operator + (InformationAboutScanning lhs,InformationAboutScanning rhs)
    {
        InformationAboutScanning newInfo = new InformationAboutScanning();
        newInfo.CountFiles += lhs.CountFiles + rhs.CountFiles;
        newInfo.CountJSfiles += lhs.CountJSfiles + rhs.CountJSfiles;
        newInfo.CountRmDetecs += lhs.CountRmDetecs + rhs.CountRmDetecs;
        newInfo.CountRundll32Detecs += lhs.CountRundll32Detecs + rhs.CountRundll32Detecs;
        newInfo.CountOtherErrors += lhs.CountOtherErrors + rhs.CountOtherErrors;

        return newInfo;
    }
}