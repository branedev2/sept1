using System;
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Http;
using System.Runtime.Remoting.Channels.Tcp;
using System.Runtime.Serialization.Formatters;
using System.Collections;
using System.Security;
using System.Net;
using System.IO;
using System.Runtime.Remoting.Messaging;

// True Positives (Vulnerable Code Examples)

public class bad_case_1
{
    public void ConfigureRemotingServer()
    {
        // Setting up a TCP channel with TypeFilterLevel.Full
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        // ruleid: insecure-typefilterlevel-full-csharp-rule
        serverProvider.TypeFilterLevel = TypeFilterLevel.Full;
        
        IDictionary props = new Hashtable();
        props["port"] = 8085;
        
        TcpChannel channel = new TcpChannel(props, null, serverProvider);
        ChannelServices.RegisterChannel(channel, false);
        RemotingConfiguration.RegisterWellKnownServiceType(typeof(RemoteService), "RemoteService", WellKnownObjectMode.Singleton);
    }
}

public class bad_case_2
{
    public void SetupRemotingWithFullTypeFilter()
    {
        // Setting up an HTTP channel with TypeFilterLevel.Full
        HttpServerChannel channel = new HttpServerChannel(8086);
        ChannelServices.RegisterChannel(channel, false);
        
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        // ruleid: insecure-typefilterlevel-full-csharp-rule
        serverProvider.TypeFilterLevel = TypeFilterLevel.Full;
        
        RemotingConfiguration.RegisterWellKnownServiceType(typeof(RemoteService), "RemoteService", WellKnownObjectMode.Singleton);
    }
}

public class bad_case_3
{
    public void ConfigureMultipleChannels()
    {
        // Configure multiple channels with TypeFilterLevel.Full
        BinaryServerFormatterSinkProvider serverProvider1 = new BinaryServerFormatterSinkProvider();
        // ruleid: insecure-typefilterlevel-full-csharp-rule
        serverProvider1.TypeFilterLevel = TypeFilterLevel.Full;
        
        TcpChannel tcpChannel = new TcpChannel(8087, null, serverProvider1);
        ChannelServices.RegisterChannel(tcpChannel, false);
        
        BinaryServerFormatterSinkProvider serverProvider2 = new BinaryServerFormatterSinkProvider();
        // ruleid: insecure-typefilterlevel-full-csharp-rule
        serverProvider2.TypeFilterLevel = TypeFilterLevel.Full;
        
        HttpChannel httpChannel = new HttpChannel(8088, null, serverProvider2);
        ChannelServices.RegisterChannel(httpChannel, false);
    }
}

public class bad_case_4
{
    public void ConfigureRemotingWithProperties()
    {
        // Using properties dictionary to set TypeFilterLevel to Full
        IDictionary properties = new Hashtable();
        properties["port"] = 8089;
        
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        // ruleid: insecure-typefilterlevel-full-csharp-rule
        serverProvider.TypeFilterLevel = TypeFilterLevel.Full;
        
        TcpServerChannel channel = new TcpServerChannel(properties, serverProvider);
        ChannelServices.RegisterChannel(channel, false);
    }
}

public class bad_case_5
{
    public void SetupRemotingWithConditionalTypeFilter(bool isSecure)
    {
        // Even with a condition, setting TypeFilterLevel to Full is insecure
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        
        if (!isSecure)
        {
            // ruleid: insecure-typefilterlevel-full-csharp-rule
            serverProvider.TypeFilterLevel = TypeFilterLevel.Full;
        }
        
        TcpChannel channel = new TcpChannel(8090, null, serverProvider);
        ChannelServices.RegisterChannel(channel, false);
    }
}

public class bad_case_6
{
    public void ConfigureRemotingWithVariable()
    {
        // Using a variable to set TypeFilterLevel to Full
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        TypeFilterLevel level = TypeFilterLevel.Full;
        // ruleid: insecure-typefilterlevel-full-csharp-rule
        serverProvider.TypeFilterLevel = level;
        
        TcpChannel channel = new TcpChannel(8091, null, serverProvider);
        ChannelServices.RegisterChannel(channel, false);
    }
}

public class bad_case_7
{
    public void SetupRemotingInLoop()
    {
        // Setting up multiple channels in a loop, all with TypeFilterLevel.Full
        for (int port = 8092; port < 8095; port++)
        {
            BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
            // ruleid: insecure-typefilterlevel-full-csharp-rule
            serverProvider.TypeFilterLevel = TypeFilterLevel.Full;
            
            IDictionary props = new Hashtable();
            props["port"] = port;
            
            TcpChannel channel = new TcpChannel(props, null, serverProvider);
            ChannelServices.RegisterChannel(channel, false);
        }
    }
}

public class bad_case_8
{
    public void ConfigureRemotingWithCustomFormatter()
    {
        // Using a custom formatter but still with TypeFilterLevel.Full
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        // ruleid: insecure-typefilterlevel-full-csharp-rule
        serverProvider.TypeFilterLevel = TypeFilterLevel.Full;
        
        serverProvider.Next = new SoapServerFormatterSinkProvider();
        
        TcpChannel channel = new TcpChannel(8095, null, serverProvider);
        ChannelServices.RegisterChannel(channel, false);
    }
}

public class bad_case_9
{
    public void SetupRemotingWithSecurity()
    {
        // Even with security settings, TypeFilterLevel.Full is still insecure
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        // ruleid: insecure-typefilterlevel-full-csharp-rule
        serverProvider.TypeFilterLevel = TypeFilterLevel.Full;
        
        IDictionary props = new Hashtable();
        props["port"] = 8096;
        props["secure"] = true;
        props["impersonationLevel"] = "Impersonation";
        
        TcpChannel channel = new TcpChannel(props, null, serverProvider);
        ChannelServices.RegisterChannel(channel, true); // Secure is true
    }
}

public class bad_case_10
{
    public void ConfigureRemotingWithHelperMethod()
    {
        // Using a helper method but still setting TypeFilterLevel.Full
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        SetTypeFilterLevel(serverProvider);
        
        TcpChannel channel = new TcpChannel(8097, null, serverProvider);
        ChannelServices.RegisterChannel(channel, false);
    }
    
    private void SetTypeFilterLevel(BinaryServerFormatterSinkProvider provider)
    {
        // ruleid: insecure-typefilterlevel-full-csharp-rule
        provider.TypeFilterLevel = TypeFilterLevel.Full;
    }
}

public class bad_case_11
{
    public void SetupRemotingWithDynamicPort(int port)
    {
        // Dynamic port but static TypeFilterLevel.Full
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        // ruleid: insecure-typefilterlevel-full-csharp-rule
        serverProvider.TypeFilterLevel = TypeFilterLevel.Full;
        
        IDictionary props = new Hashtable();
        props["port"] = port;
        
        TcpChannel channel = new TcpChannel(props, null, serverProvider);
        ChannelServices.RegisterChannel(channel, false);
    }
}

public class bad_case_12
{
    public void ConfigureRemotingWithSoapAndBinary()
    {
        // Using both SOAP and Binary formatters with TypeFilterLevel.Full
        BinaryServerFormatterSinkProvider binaryProvider = new BinaryServerFormatterSinkProvider();
        // ruleid: insecure-typefilterlevel-full-csharp-rule
        binaryProvider.TypeFilterLevel = TypeFilterLevel.Full;
        
        SoapServerFormatterSinkProvider soapProvider = new SoapServerFormatterSinkProvider();
        
        TcpChannel tcpChannel = new TcpChannel(8098, null, binaryProvider);
        HttpChannel httpChannel = new HttpChannel(8099, null, soapProvider);
        
        ChannelServices.RegisterChannel(tcpChannel, false);
        ChannelServices.RegisterChannel(httpChannel, false);
    }
}

public class bad_case_13
{
    public void SetupRemotingWithCustomChannel()
    {
        // Custom channel configuration but still with TypeFilterLevel.Full
        IDictionary properties = new Hashtable();
        properties["port"] = 9000;
        properties["name"] = "CustomTcpChannel";
        
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        // ruleid: insecure-typefilterlevel-full-csharp-rule
        serverProvider.TypeFilterLevel = TypeFilterLevel.Full;
        
        IServerChannelSinkProvider chain = serverProvider;
        chain.Next = new BinaryServerFormatterSinkProvider();
        
        TcpServerChannel channel = new TcpServerChannel(properties, chain);
        ChannelServices.RegisterChannel(channel, false);
    }
}

public class bad_case_14
{
    public void ConfigureRemotingWithSwitch()
    {
        // Using a switch statement but still setting TypeFilterLevel.Full
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        
        string securityLevel = "low"; // This could come from a config
        switch (securityLevel)
        {
            case "high":
                // Even in high security, using Full is insecure
                // ruleid: insecure-typefilterlevel-full-csharp-rule
                serverProvider.TypeFilterLevel = TypeFilterLevel.Full;
                break;
            case "medium":
            case "low":
            default:
                // ruleid: insecure-typefilterlevel-full-csharp-rule
                serverProvider.TypeFilterLevel = TypeFilterLevel.Full;
                break;
        }
        
        TcpChannel channel = new TcpChannel(9001, null, serverProvider);
        ChannelServices.RegisterChannel(channel, false);
    }
}

public class bad_case_15
{
    public void SetupRemotingWithTryCatch()
    {
        // Using try-catch but still setting TypeFilterLevel.Full
        try
        {
            BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
            // ruleid: insecure-typefilterlevel-full-csharp-rule
            serverProvider.TypeFilterLevel = TypeFilterLevel.Full;
            
            TcpChannel channel = new TcpChannel(9002, null, serverProvider);
            ChannelServices.RegisterChannel(channel, false);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error setting up remoting: " + ex.Message);
        }
    }
}

// True Negatives (Secure Code Examples)

public class good_case_1
{
    public void ConfigureRemotingServerSecurely()
    {
        // Setting up a TCP channel with TypeFilterLevel.Low
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        // ok: insecure-typefilterlevel-full-csharp-rule
        serverProvider.TypeFilterLevel = TypeFilterLevel.Low;
        
        IDictionary props = new Hashtable();
        props["port"] = 8085;
        
        TcpChannel channel = new TcpChannel(props, null, serverProvider);
        ChannelServices.RegisterChannel(channel, false);
        RemotingConfiguration.RegisterWellKnownServiceType(typeof(RemoteService), "RemoteService", WellKnownObjectMode.Singleton);
    }
}

public class good_case_2
{
    public void SetupRemotingWithLowTypeFilter()
    {
        // Setting up an HTTP channel with TypeFilterLevel.Low
        HttpServerChannel channel = new HttpServerChannel(8086);
        ChannelServices.RegisterChannel(channel, false);
        
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        // ok: insecure-typefilterlevel-full-csharp-rule
        serverProvider.TypeFilterLevel = TypeFilterLevel.Low;
        
        RemotingConfiguration.RegisterWellKnownServiceType(typeof(RemoteService), "RemoteService", WellKnownObjectMode.Singleton);
    }
}

public class good_case_3
{
    public void ConfigureMultipleChannelsSecurely()
    {
        // Configure multiple channels with TypeFilterLevel.Low
        BinaryServerFormatterSinkProvider serverProvider1 = new BinaryServerFormatterSinkProvider();
        // ok: insecure-typefilterlevel-full-csharp-rule
        serverProvider1.TypeFilterLevel = TypeFilterLevel.Low;
        
        TcpChannel tcpChannel = new TcpChannel(8087, null, serverProvider1);
        ChannelServices.RegisterChannel(tcpChannel, false);
        
        BinaryServerFormatterSinkProvider serverProvider2 = new BinaryServerFormatterSinkProvider();
        // ok: insecure-typefilterlevel-full-csharp-rule
        serverProvider2.TypeFilterLevel = TypeFilterLevel.Low;
        
        HttpChannel httpChannel = new HttpChannel(8088, null, serverProvider2);
        ChannelServices.RegisterChannel(httpChannel, false);
    }
}

public class good_case_4
{
    public void UseWCFInsteadOfRemoting()
    {
        // Using WCF instead of .NET Remoting (recommended approach)
        // ok: insecure-typefilterlevel-full-csharp-rule
        // This is a placeholder for WCF setup which is the recommended alternative
        // In a real implementation, you would use ServiceHost and appropriate WCF configurations
        Console.WriteLine("Using WCF for secure communication instead of .NET Remoting");
        
        // Example WCF setup would go here
        // ServiceHost host = new ServiceHost(typeof(MyService));
        // host.AddServiceEndpoint(typeof(IMyService), new NetTcpBinding(), "net.tcp://localhost:8085/MyService");
        // host.Open();
    }
}

public class good_case_5
{
    public void ConfigureRemotingWithPropertiesSecurely()
    {
        // Using properties dictionary with TypeFilterLevel.Low
        IDictionary properties = new Hashtable();
        properties["port"] = 8089;
        
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        // ok: insecure-typefilterlevel-full-csharp-rule
        serverProvider.TypeFilterLevel = TypeFilterLevel.Low;
        
        TcpServerChannel channel = new TcpServerChannel(properties, serverProvider);
        ChannelServices.RegisterChannel(channel, false);
    }
}

public class good_case_6
{
    public void SetupRemotingWithConditionalTypeFilterSecure(bool isSecure)
    {
        // Using a condition to ensure TypeFilterLevel is always Low
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        
        if (isSecure)
        {
            // ok: insecure-typefilterlevel-full-csharp-rule
            serverProvider.TypeFilterLevel = TypeFilterLevel.Low;
        }
        else
        {
            // ok: insecure-typefilterlevel-full-csharp-rule
            serverProvider.TypeFilterLevel = TypeFilterLevel.Low;
        }
        
        TcpChannel channel = new TcpChannel(8090, null, serverProvider);
        ChannelServices.RegisterChannel(channel, false);
    }
}

public class good_case_7
{
    public void ConfigureRemotingWithVariableSecurely()
    {
        // Using a variable to set TypeFilterLevel to Low
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        TypeFilterLevel level = TypeFilterLevel.Low;
        // ok: insecure-typefilterlevel-full-csharp-rule
        serverProvider.TypeFilterLevel = level;
        
        TcpChannel channel = new TcpChannel(8091, null, serverProvider);
        ChannelServices.RegisterChannel(channel, false);
    }
}

public class good_case_8
{
    public void SetupRemotingInLoopSecurely()
    {
        // Setting up multiple channels in a loop, all with TypeFilterLevel.Low
        for (int port = 8092; port < 8095; port++)
        {
            BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
            // ok: insecure-typefilterlevel-full-csharp-rule
            serverProvider.TypeFilterLevel = TypeFilterLevel.Low;
            
            IDictionary props = new Hashtable();
            props["port"] = port;
            
            TcpChannel channel = new TcpChannel(props, null, serverProvider);
            ChannelServices.RegisterChannel(channel, false);
        }
    }
}

public class good_case_9
{
    public void ConfigureRemotingWithCustomFormatterSecurely()
    {
        // Using a custom formatter with TypeFilterLevel.Low
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        // ok: insecure-typefilterlevel-full-csharp-rule
        serverProvider.TypeFilterLevel = TypeFilterLevel.Low;
        
        serverProvider.Next = new SoapServerFormatterSinkProvider();
        
        TcpChannel channel = new TcpChannel(8095, null, serverProvider);
        ChannelServices.RegisterChannel(channel, false);
    }
}

public class good_case_10
{
    public void SetupRemotingWithSecurityAndLowTypeFilter()
    {
        // Using security settings with TypeFilterLevel.Low
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        // ok: insecure-typefilterlevel-full-csharp-rule
        serverProvider.TypeFilterLevel = TypeFilterLevel.Low;
        
        IDictionary props = new Hashtable();
        props["port"] = 8096;
        props["secure"] = true;
        props["impersonationLevel"] = "Impersonation";
        
        TcpChannel channel = new TcpChannel(props, null, serverProvider);
        ChannelServices.RegisterChannel(channel, true); // Secure is true
    }
}

public class good_case_11
{
    public void ConfigureRemotingWithHelperMethodSecurely()
    {
        // Using a helper method to set TypeFilterLevel.Low
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        SetTypeFilterLevelSecurely(serverProvider);
        
        TcpChannel channel = new TcpChannel(8097, null, serverProvider);
        ChannelServices.RegisterChannel(channel, false);
    }
    
    private void SetTypeFilterLevelSecurely(BinaryServerFormatterSinkProvider provider)
    {
        // ok: insecure-typefilterlevel-full-csharp-rule
        provider.TypeFilterLevel = TypeFilterLevel.Low;
    }
}

public class good_case_12
{
    public void SetupRemotingWithDynamicPortSecurely(int port)
    {
        // Dynamic port with TypeFilterLevel.Low
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        // ok: insecure-typefilterlevel-full-csharp-rule
        serverProvider.TypeFilterLevel = TypeFilterLevel.Low;
        
        IDictionary props = new Hashtable();
        props["port"] = port;
        
        TcpChannel channel = new TcpChannel(props, null, serverProvider);
        ChannelServices.RegisterChannel(channel, false);
    }
}

public class good_case_13
{
    public void ConfigureRemotingWithSoapAndBinarySecurely()
    {
        // Using both SOAP and Binary formatters with TypeFilterLevel.Low
        BinaryServerFormatterSinkProvider binaryProvider = new BinaryServerFormatterSinkProvider();
        // ok: insecure-typefilterlevel-full-csharp-rule
        binaryProvider.TypeFilterLevel = TypeFilterLevel.Low;
        
        SoapServerFormatterSinkProvider soapProvider = new SoapServerFormatterSinkProvider();
        
        TcpChannel tcpChannel = new TcpChannel(8098, null, binaryProvider);
        HttpChannel httpChannel = new HttpChannel(8099, null, soapProvider);
        
        ChannelServices.RegisterChannel(tcpChannel, false);
        ChannelServices.RegisterChannel(httpChannel, false);
    }
}

public class good_case_14
{
    public void SetupRemotingWithCustomChannelSecurely()
    {
        // Custom channel configuration with TypeFilterLevel.Low
        IDictionary properties = new Hashtable();
        properties["port"] = 9000;
        properties["name"] = "CustomTcpChannel";
        
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        // ok: insecure-typefilterlevel-full-csharp-rule
        serverProvider.TypeFilterLevel = TypeFilterLevel.Low;
        
        IServerChannelSinkProvider chain = serverProvider;
        chain.Next = new BinaryServerFormatterSinkProvider();
        
        TcpServerChannel channel = new TcpServerChannel(properties, chain);
        ChannelServices.RegisterChannel(channel, false);
    }
}

public class good_case_15
{
    public void ConfigureRemotingWithSwitchSecurely()
    {
        // Using a switch statement to always set TypeFilterLevel.Low
        BinaryServerFormatterSinkProvider serverProvider = new BinaryServerFormatterSinkProvider();
        
        string securityLevel = "low"; // This could come from a config
        switch (securityLevel)
        {
            case "high":
                // ok: insecure-typefilterlevel-full-csharp-rule
                serverProvider.TypeFilterLevel = TypeFilterLevel.Low;
                break;
            case "medium":
            case "low":
            default:
                // ok: insecure-typefilterlevel-full-csharp-rule
                serverProvider.TypeFilterLevel = TypeFilterLevel.Low;
                break;
        }
        
        TcpChannel channel = new TcpChannel(9001, null, serverProvider);
        ChannelServices.RegisterChannel(channel, false);
    }
}

// Helper class for examples
public class RemoteService : MarshalByRefObject
{
    public string GetMessage()
    {
        return "Hello from remote service!";
    }
}