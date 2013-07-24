using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Mvc;
using System.Web.Routing;
using System.Web.Mvc.Html;
using ExtendedMongoMembership.Helpers.mvc;

namespace System.Web.Mvc
{
    public static class ActionLinkHelper
    {
        public static MvcHtmlString PermissionActionLink(this HtmlHelper htmlHelper, string linkText, string actionName, bool showActionLinkAsDisabled = false)
        {
            return htmlHelper.PermissionActionLink(linkText, actionName, null, new RouteValueDictionary(), new RouteValueDictionary(), showActionLinkAsDisabled);
        }

        public static MvcHtmlString PermissionActionLink(this HtmlHelper htmlHelper, string linkText, string actionName, object routeValues, bool showActionLinkAsDisabled = false)
        {
            return htmlHelper.PermissionActionLink(linkText, actionName, null, new RouteValueDictionary(routeValues), new RouteValueDictionary(), showActionLinkAsDisabled);
        }

        public static MvcHtmlString PermissionActionLink(this HtmlHelper htmlHelper, string linkText, string actionName, string controllerName, bool showActionLinkAsDisabled = false)
        {
            return htmlHelper.PermissionActionLink(linkText, actionName, controllerName, new RouteValueDictionary(), new RouteValueDictionary(), showActionLinkAsDisabled);
        }

        public static MvcHtmlString PermissionActionLink(this HtmlHelper htmlHelper, string linkText, string actionName, RouteValueDictionary routeValues, bool showActionLinkAsDisabled = false)
        {
            return htmlHelper.PermissionActionLink(linkText, actionName, null, routeValues, new RouteValueDictionary(), showActionLinkAsDisabled);
        }

        public static MvcHtmlString PermissionActionLink(this HtmlHelper htmlHelper, string linkText, string actionName, object routeValues, object htmlAttributes, bool showActionLinkAsDisabled = false)
        {
            return htmlHelper.PermissionActionLink(linkText, actionName, null, new RouteValueDictionary(routeValues), new RouteValueDictionary(htmlAttributes), showActionLinkAsDisabled);
        }

        public static MvcHtmlString PermissionActionLink(this HtmlHelper htmlHelper, string linkText, string actionName, RouteValueDictionary routeValues, IDictionary<string, object> htmlAttributes, bool showActionLinkAsDisabled = false)
        {
            return htmlHelper.PermissionActionLink(linkText, actionName, null, routeValues, htmlAttributes, showActionLinkAsDisabled);
        }

        public static MvcHtmlString PermissionActionLink(this HtmlHelper htmlHelper, string linkText, string actionName, string controllerName, object routeValues, object htmlAttributes, bool showActionLinkAsDisabled = false)
        {
            return htmlHelper.PermissionActionLink(linkText, actionName, controllerName, new RouteValueDictionary(routeValues), new RouteValueDictionary(htmlAttributes), showActionLinkAsDisabled);
        }

        public static MvcHtmlString PermissionActionLink(this HtmlHelper htmlHelper, string linkText, string actionName, string controllerName, RouteValueDictionary routeValues, IDictionary<string, object> htmlAttributes, bool showActionLinkAsDisabled)
        {
            if (htmlHelper.ActionAuthorized(actionName, controllerName))
            {
                return htmlHelper.ActionLink(linkText, actionName, controllerName, routeValues, htmlAttributes);
            }
            else
            {
                if (showActionLinkAsDisabled)
                {
                    TagBuilder tagBuilder = new TagBuilder("span");
                    tagBuilder.InnerHtml = linkText;
                    return MvcHtmlString.Create(tagBuilder.ToString());
                }
                else
                {
                    return MvcHtmlString.Empty;
                }
            }
        }
    }
}
