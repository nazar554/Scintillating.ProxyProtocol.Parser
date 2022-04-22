using System.Reflection;
using Xunit;

namespace Scintillating.ProxyProtocol.Parser.Tests.Infrastructure;

public class IntrinsicsFact : FactAttribute
{
    public IntrinsicsFact(Type type)
    {
        var property = type.GetProperty("IsSupported", BindingFlags.Static | BindingFlags.Public | BindingFlags.DeclaredOnly);
        var method = property!.GetGetMethod();
        var func = (Func<bool>)Delegate.CreateDelegate(typeof(Func<bool>), method!);
        if (!func())
        {
            Skip = $"{type} is not supported on this machine.";
        }
    }
}
