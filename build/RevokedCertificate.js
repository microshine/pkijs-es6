"use strict";

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _asn1js = require("asn1js");

var asn1js = _interopRequireWildcard(_asn1js);

var _pvutils = require("pvutils");

var _Time = require("./Time");

var _Time2 = _interopRequireDefault(_Time);

var _Extensions = require("./Extensions");

var _Extensions2 = _interopRequireDefault(_Extensions);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//**************************************************************************************

var RevokedCertificate = function () {
	//**********************************************************************************
	/**
  * Constructor for RevokedCertificate class
  * @param {Object} [parameters={}]
  * @property {Object} [schema] asn1js parsed value
  */

	function RevokedCertificate() {
		var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

		_classCallCheck(this, RevokedCertificate);

		//region Internal properties of the object
		/**
   * @type {Integer}
   * @description userCertificate
   */
		this.userCertificate = (0, _pvutils.getParametersValue)(parameters, "userCertificate", RevokedCertificate.defaultValues("userCertificate"));
		/**
   * @type {Time}
   * @description revocationDate
   */
		this.revocationDate = (0, _pvutils.getParametersValue)(parameters, "revocationDate", RevokedCertificate.defaultValues("revocationDate"));

		if ("crlEntryExtensions" in parameters)
			/**
    * @type {Extensions}
    * @description crlEntryExtensions
    */
			this.crlEntryExtensions = (0, _pvutils.getParametersValue)(parameters, "crlEntryExtensions", RevokedCertificate.defaultValues("crlEntryExtensions"));
		//endregion

		//region If input argument array contains "schema" for this object
		if ("schema" in parameters) this.fromSchema(parameters.schema);
		//endregion
	}
	//**********************************************************************************
	/**
  * Return default values for all class members
  * @param {string} memberName String name for a class member
  */


	_createClass(RevokedCertificate, [{
		key: "fromSchema",

		//**********************************************************************************
		/**
   * Convert parsed asn1js object into current class
   * @param {!Object} schema
   */
		value: function fromSchema(schema) {
			//region Check the schema is valid
			var asn1 = asn1js.compareSchema(schema, schema, RevokedCertificate.schema());

			if (asn1.verified === false) throw new Error("Object's schema was not verified against input data for REV_CERT");
			//endregion

			//region Get internal properties from parsed schema
			this.userCertificate = asn1.result.userCertificate;
			this.revocationDate = new _Time2.default({ schema: asn1.result.revocationDate });

			if ("crlEntryExtensions" in asn1.result) this.crlEntryExtensions = new _Extensions2.default({ schema: asn1.result.crlEntryExtensions });
			//endregion
		}
		//**********************************************************************************
		/**
   * Convert current object to asn1js object and set correct values
   * @returns {Object} asn1js object
   */

	}, {
		key: "toSchema",
		value: function toSchema() {
			//region Create array for output sequence
			var outputArray = [this.userCertificate, this.revocationDate.toSchema()];

			if ("crlEntryExtensions" in this) outputArray.push(this.crlEntryExtensions.toSchema());
			//endregion

			//region Construct and return new ASN.1 schema for this object
			return new asn1js.Sequence({
				value: outputArray
			});
			//endregion
		}
		//**********************************************************************************
		/**
   * Convertion for the class to JSON object
   * @returns {Object}
   */

	}, {
		key: "toJSON",
		value: function toJSON() {
			var object = {
				userCertificate: this.userCertificate.toJSON(),
				revocationDate: this.revocationDate.toJSON
			};

			if ("crlEntryExtensions" in this) object.crlEntryExtensions = this.crlEntryExtensions.toJSON();

			return object;
		}
		//**********************************************************************************

	}], [{
		key: "defaultValues",
		value: function defaultValues(memberName) {
			switch (memberName) {
				case "userCertificate":
					return new asn1js.Integer();
				case "revocationDate":
					return new _Time2.default();
				case "crlEntryExtensions":
					return new _Extensions2.default();
				default:
					throw new Error("Invalid member name for RevokedCertificate class: " + memberName);
			}
		}
		//**********************************************************************************
		/**
   * Return value of asn1js schema for current class
   * @param {Object} parameters Input parameters for the schema
   * @returns {Object} asn1js schema object
   */

	}, {
		key: "schema",
		value: function schema() {
			var parameters = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];

			/**
    * @type {Object}
    * @property {string} [blockName]
    * @property {string} [userCertificate]
    * @property {string} [revocationDate]
    * @property {string} [crlEntryExtensions]
    */
			var names = (0, _pvutils.getParametersValue)(parameters, "names", {});

			return new asn1js.Sequence({
				name: names.blockName || "",
				value: [new asn1js.Integer({ name: names.userCertificate || "userCertificate" }), _Time2.default.schema({
					names: {
						utcTimeName: names.revocationDate || "revocationDate",
						generalTimeName: names.revocationDate || "revocationDate"
					}
				}), _Extensions2.default.schema({
					names: {
						blockName: names.crlEntryExtensions || "crlEntryExtensions"
					}
				}, true)]
			});
		}
	}]);

	return RevokedCertificate;
}();
//**************************************************************************************


exports.default = RevokedCertificate;
//# sourceMappingURL=RevokedCertificate.js.map