using GlobalMessenger.Core.Constants;

namespace GlobalMessenger.Core
{

	/// <summary>
	/// Class used to log additional information relating to a request in serilog
	/// </summary>
	public class Requester
	{

		public string IpAddress { get; set; }

		public string LoggedOnUser { get; set; }

		public string LoggedOnUserId { get; set; }

		public AppSensorDetectionPointKind? AppSensorDetectionPoint { get; set; }

		public string SessionId { get; set; }

	}
}