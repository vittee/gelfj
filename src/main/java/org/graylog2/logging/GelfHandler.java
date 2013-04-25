package org.graylog2.logging;

import org.graylog2.GelfMessage;
import org.graylog2.GelfSender;
import org.graylog2.GelfTCPSender;
import org.graylog2.GelfUDPSender;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.IllegalFormatConversionException;
import java.util.Map;
import java.util.logging.*;

public class GelfHandler
        extends Handler
{
    private static final int MAX_SHORT_MESSAGE_LENGTH = 250;
    private static final Map<String, Integer> LOG4J_LOGLEVELS;

    private enum SyslogLevels {
        EMERGENCY(0),
        ALERT(1),
        CRITICAL(2),
        ERROR(3),
        WARNING(4),
        NOTICE(5),
        INFORMAT(6),
        DEBUG(7);

        private int level;

        private SyslogLevels(int level) {
            this.level = level;
        }

        public int getLevel() {
            return this.level;
        }

    }

    static {

        Map<String, Integer> log4jMap = new HashMap<String, Integer>(6);
        log4jMap.put("FATAL", SyslogLevels.CRITICAL.getLevel());
        log4jMap.put("ERROR", SyslogLevels.ERROR.getLevel());
        log4jMap.put("WARN", SyslogLevels.WARNING.getLevel());
        log4jMap.put("INFO", SyslogLevels.INFORMAT.getLevel());
        log4jMap.put("DEBUG", SyslogLevels.DEBUG.getLevel());
        log4jMap.put("TRACE", SyslogLevels.DEBUG.getLevel());

        LOG4J_LOGLEVELS = log4jMap;
    }

    private String graylogHost;
    private String originHost;
    private int graylogPort;
    private String facility;
    private GelfSender gelfSender;
    private boolean extractStacktrace;
    private Map<String, String> fields;

    public GelfHandler()
    {
        final LogManager manager = LogManager.getLogManager();
        final String prefix = getClass().getName();

        graylogHost = manager.getProperty( prefix + ".graylogHost" );
        final String port = manager.getProperty( prefix + ".graylogPort" );
        graylogPort = null == port ? 12201 : Integer.parseInt( port );
        originHost = manager.getProperty( prefix + ".originHost" );
        extractStacktrace = "true".equalsIgnoreCase( manager.getProperty( prefix + ".extractStacktrace" ) );
        int fieldNumber = 0;
        fields = new HashMap<String, String>(  );
        while( true )
        {
            final String property = manager.getProperty( prefix + ".additionalField." + fieldNumber );
            if ( null == property )
            {
                break;
            }
            final int index = property.indexOf( '=' );
            if( -1 != index )
            {
                fields.put( property.substring( 0, index ), property.substring( index + 1 ) );
            }

            fieldNumber++;
        }
        facility = manager.getProperty( prefix + ".facility" );


        final String level = manager.getProperty( prefix + ".level" );
        if ( null != level )
        {
            setLevel( Level.parse( level.trim() ) );
        }
        else
        {
            setLevel( Level.INFO );
        }

        final String filter = manager.getProperty( prefix + ".filter" );
        try
        {
            if ( null != filter )
            {
                final Class clazz = ClassLoader.getSystemClassLoader().loadClass( filter );
                setFilter( (Filter) clazz.newInstance() );
            }
        }
        catch ( final Exception e )
        {
            //ignore
        }
        //This only used for testing
        final String testSender = manager.getProperty( prefix + ".graylogTestSenderClass" );
        try
        {
            if ( null != testSender )
            {
                final Class clazz = ClassLoader.getSystemClassLoader().loadClass( testSender );
                gelfSender = (GelfSender) clazz.newInstance();
            }
        }
        catch ( final Exception e )
        {
            //ignore
        }
    }

    @Override
    public synchronized void flush()
    {
    }


    private String getOriginHost()
    {
        if ( null == originHost )
        {
            originHost = getLocalHostName();
        }
        return originHost;
    }

    private String getLocalHostName()
    {
        try
        {
            return InetAddress.getLocalHost().getHostName();
        }
        catch ( final UnknownHostException uhe )
        {
            reportError( "Unknown local hostname", uhe, ErrorManager.GENERIC_FAILURE );
        }

        return null;
    }

    @Override
    public synchronized void publish( final LogRecord record )
    {
        if ( !isLoggable( record ) )
        {
            return;
        }
        if ( null == gelfSender )
        {
			if (graylogHost == null) {
				reportError("Graylog2 hostname is empty!", null, ErrorManager.WRITE_FAILURE);
			} else {
				try
				{
					if (graylogHost.startsWith("tcp:")) {
						String tcpGraylogHost = graylogHost.substring(0, 4);
						gelfSender = new GelfTCPSender(tcpGraylogHost, graylogPort);
					} else if (graylogHost.startsWith("udp:")) {
						String udpGraylogHost = graylogHost.substring(0, 4);
						gelfSender = new GelfUDPSender(udpGraylogHost, graylogPort);
					} else {
						gelfSender = new GelfUDPSender(graylogHost, graylogPort);
					}
				}
				catch ( UnknownHostException e )
				{
					reportError( "Unknown Graylog2 hostname:" + graylogHost, e, ErrorManager.WRITE_FAILURE );
				}
				catch ( SocketException e )
				{
					reportError( "Socket exception", e, ErrorManager.WRITE_FAILURE );
				}
				catch ( IOException e )
				{
					reportError( "IO exception", e, ErrorManager.WRITE_FAILURE );
				}
			}
		}
        if ( null == gelfSender ||
                !gelfSender.sendMessage( makeMessage( record ) ) )
        {
            reportError( "Could not send GELF message", null, ErrorManager.WRITE_FAILURE );
        }
    }

    @Override
    public void close()
    {
        if ( null != gelfSender )
        {
            gelfSender.close();
            gelfSender = null;
        }
    }

    private GelfMessage makeMessage( final LogRecord record )
    {
        String message = record.getMessage();
        Object[] parameters = record.getParameters();

        if (message == null) message = "";
        if ( parameters != null && parameters.length > 0 )
        {
            //by default, using {0}, {1}, etc. -> MessageFormat
            message = MessageFormat.format( message, parameters );

            if(message.equals(record.getMessage())) {
                //if the text is the same, assuming this is String.format type log (%s, %d, etc.)
                try {
                    message = String.format( message, parameters );
                } catch (IllegalFormatConversionException e ) {
                    //leaving message as it is to avoid compatibility problems
                    message = record.getMessage();
                } catch (NullPointerException e) {
                    //ignore
                }
            }
        }

        final String shortMessage;
        if ( message.length() > MAX_SHORT_MESSAGE_LENGTH )
        {
            shortMessage = message.substring( 0, MAX_SHORT_MESSAGE_LENGTH - 1 );
        }
        else
        {
            shortMessage = message;
        }

        if ( extractStacktrace )
        {
            final Throwable thrown = record.getThrown();
            if ( null != thrown )
            {
                final StringWriter sw = new StringWriter();
                thrown.printStackTrace( new PrintWriter( sw ) );
                message += "\n\r" + sw.toString();
            }
        }

        final GelfMessage gelfMessage =
                new GelfMessage( shortMessage,
                        message,
                        record.getMillis(),
                        String.valueOf( levelToSyslogLevel( record.getLevel() ) ) );
        gelfMessage.addField( "SourceClassName", record.getSourceClassName() );
        gelfMessage.addField( "SourceMethodName", record.getSourceMethodName() );

        if ( null != getOriginHost() )
        {
            gelfMessage.setHost( getOriginHost() );
        }

        if ( null != facility )
        {
            gelfMessage.setFacility( facility );
        }

        if ( null != fields )
        {
            for ( final Map.Entry<String, String> entry : fields.entrySet() )
            {
                gelfMessage.addField( entry.getKey(), entry.getValue() );
            }
        }

        return gelfMessage;
    }

    private int levelToSyslogLevel( final Level level )
    {
        final int syslogLevel;
        if ( level == Level.SEVERE )
        {
            syslogLevel = SyslogLevels.ERROR.getLevel();
        }
        else if ( level == Level.WARNING )
        {
            syslogLevel = SyslogLevels.WARNING.getLevel();
        }
        else if ( level == Level.INFO )
        {
            syslogLevel = SyslogLevels.INFORMAT.getLevel();
        }
        else
        {
            //try to figure out loglevel
            Integer log4jLevel = LOG4J_LOGLEVELS.get(level.getName());
            syslogLevel = log4jLevel == null ? 7 : log4jLevel;
        }
        return syslogLevel;
    }

    public void setExtractStacktrace(boolean extractStacktrace) {
        this.extractStacktrace = extractStacktrace;
    }

    public void setGraylogPort(int graylogPort) {
        this.graylogPort = graylogPort;
    }

    public void setOriginHost(String originHost) {
        this.originHost = originHost;
    }

    public void setGraylogHost(String graylogHost) {
        this.graylogHost = graylogHost;
    }

    public void setFacility(String facility) {
        this.facility = facility;
    }
}
