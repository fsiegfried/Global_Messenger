using System.Collections.Generic;
using System.Web.Mvc;

namespace GlobalMessenger.Core
{
	public interface IAppSensor
	{
		void ValidateFormData(Controller controller, List<string> expectedFormKeys);
		void InspectModelStateErrors(Controller controller);
	}
}
